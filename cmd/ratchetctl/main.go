package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"

	"github.com/sakararya43-web/Ratchet/internal/audit"
	"github.com/sakararya43-web/Ratchet/internal/ports"
	"github.com/sakararya43-web/Ratchet/internal/trust"
)

type ecdsaSignature struct {
	R, S *big.Int
}

const (
	ExitSuccess   = 0
	ExitBadArgs   = 1
	ExitQuorum    = 2
	ExitSigFailed = 3
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(ExitBadArgs)
	}

	command := os.Args[1]
	switch command {
	case "genesis":
		runGenesis(os.Args[2:])
	case "policy":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ratchetctl policy <propose|sign|activate|status|list> [flags]")
			os.Exit(ExitBadArgs)
		}
		subcmd := os.Args[2]
		switch subcmd {
		case "propose":
			runPolicyPropose(os.Args[3:])
		case "sign":
			runPolicySign(os.Args[3:])
		case "activate":
			runPolicyActivate(os.Args[3:])
		case "status":
			runPolicyStatus(os.Args[3:])
		case "list":
			runPolicyList(os.Args[3:])
		default:
			fmt.Printf("Unknown policy subcommand: %s\n", subcmd)
			os.Exit(ExitBadArgs)
		}
	case "registry":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ratchetctl registry <list|propose|sign|activate|history> [flags]")
			os.Exit(ExitBadArgs)
		}
		subcmd := os.Args[2]
		switch subcmd {
		case "list":
			runRegistryList(os.Args[3:])
		case "propose":
			runRegistryPropose(os.Args[3:])
		case "sign":
			runRegistrySign(os.Args[3:])
		case "activate":
			runRegistryActivate(os.Args[3:])
		case "history":
			runRegistryHistory(os.Args[3:])
		default:
			fmt.Printf("Unknown registry subcommand: %s\n", subcmd)
			os.Exit(ExitBadArgs)
		}
	case "audit":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ratchetctl audit <verify> [flags]")
			os.Exit(ExitBadArgs)
		}
		subcmd := os.Args[2]
		switch subcmd {
		case "verify":
			runAuditVerify(os.Args[3:])
		default:
			fmt.Printf("Unknown audit subcommand: %s\n", subcmd)
			os.Exit(ExitBadArgs)
		}
	default:
		printUsage()
		os.Exit(ExitBadArgs)
	}
}

func printUsage() {
	fmt.Println(`ratchetctl — Operational CLI for RATCHET Security Control Plane

Live Governance:
  Native Authority administration is conducted via the browser-assisted Security Policy Console
  at https://<authority-host>/security-policy using hardware-bound WebAuthn passkey assertions.

Offline Verification:
  ratchetctl audit verify --export-file=<path> [--genesis-file=<path>] [--expected-tip=<hex>] [--expected-checkpoint=<hex>] [--json]

Simulation & Test Fixtures Only (not supported for live administration):
  ratchetctl genesis --tenant=<id> --m=<threshold> --members-file=<path> [--authority-url=<url>]
  ratchetctl policy propose --bundle-file=<path> --version=<v> [--authority-url=<url>]
  ratchetctl policy sign --proposal=<id> --actor=<actor_id> --key-file=<key.pem> [--authority-url=<url>]
  ratchetctl policy activate --proposal=<id> [--authority-url=<url>]
  ratchetctl policy status [--authority-url=<url>]
  ratchetctl policy list [--authority-url=<url>]

  ratchetctl registry list [--authority-url=<url>]
  ratchetctl registry propose --members-file=<path> --m=<threshold> [--authority-url=<url>]
  ratchetctl registry sign --proposal=<id> --actor=<actor_id> --key-file=<key.pem> [--authority-url=<url>]
  ratchetctl registry activate --proposal=<id> [--authority-url=<url>]
  ratchetctl registry history [--authority-url=<url>]`)
}

func runGenesis(args []string) {
	fs := flag.NewFlagSet("genesis", flag.ExitOnError)
	tenant := fs.String("tenant", "tenant-exchange-demo", "Tenant ID")
	m := fs.Int("m", 2, "Threshold M")
	membersFile := fs.String("members-file", "", "JSON file containing Authority members")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *membersFile == "" {
		fmt.Println("Error: --members-file is required")
		os.Exit(ExitBadArgs)
	}

	data, err := os.ReadFile(*membersFile)
	if err != nil {
		fmt.Printf("Failed to read members file: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	var members []struct {
		ActorID     string `json:"actor_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"`
	}
	if err := json.Unmarshal(data, &members); err != nil {
		fmt.Printf("Invalid members JSON: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	payload := map[string]any{
		"tenant_id":   *tenant,
		"threshold_m": *m,
		"total_n":     len(members),
		"members":     members,
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(*authURL+"/api/v1/authority/genesis", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to reach authority service: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Genesis failed (HTTP %d): %s\n", resp.StatusCode, string(respBytes))
		os.Exit(ExitBadArgs)
	}

	fmt.Printf("Genesis successfully established: %s\n", string(respBytes))
}

func runPolicyPropose(args []string) {
	fs := flag.NewFlagSet("policy-propose", flag.ExitOnError)
	tenant := fs.String("tenant", "tenant-exchange-demo", "Tenant ID")
	bundleFile := fs.String("bundle-file", "", "JSON file containing bundle modules and data")
	version := fs.String("version", "v1.0.0", "Bundle version")
	description := fs.String("description", "Governed security policy update", "Proposal description")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *bundleFile == "" {
		fmt.Println("Error: --bundle-file is required")
		os.Exit(ExitBadArgs)
	}

	data, err := os.ReadFile(*bundleFile)
	if err != nil {
		fmt.Printf("Failed to read bundle file: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	var bundleContent struct {
		Modules map[string]string `json:"modules"`
		Data    map[string]any    `json:"data"`
	}
	if err := json.Unmarshal(data, &bundleContent); err != nil {
		fmt.Printf("Invalid bundle JSON: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	payload := map[string]any{
		"tenant_id":      *tenant,
		"bundle_version": *version,
		"description":    *description,
		"modules":        bundleContent.Modules,
		"data":           bundleContent.Data,
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(*authURL+"/api/v1/authority/bundle/propose", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to reach authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Proposal failed (HTTP %d): %s\n", resp.StatusCode, string(respBytes))
		os.Exit(ExitBadArgs)
	}

	fmt.Printf("Proposal created: %s\n", string(respBytes))
}

func runPolicySign(args []string) {
	fs := flag.NewFlagSet("policy-sign", flag.ExitOnError)
	proposalID := fs.String("proposal", "", "Proposal ID to sign")
	actorID := fs.String("actor", "", "Authority member actor ID")
	keyFile := fs.String("key-file", "", "Path to private key PEM for signer")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *proposalID == "" || *actorID == "" || *keyFile == "" {
		fmt.Println("Error: --proposal, --actor, and --key-file are all required")
		os.Exit(ExitBadArgs)
	}

	privKey, err := parsePrivateKey(*keyFile)
	if err != nil {
		fmt.Printf("Failed to parse private key: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	// Fetch proposal to obtain canonical bundle digest and epoch
	propResp, err := http.Get(fmt.Sprintf("%s/api/v1/authority/bundle/proposals", *authURL))
	if err != nil {
		fmt.Printf("Failed to query proposals: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = propResp.Body.Close() }()

	var proposals []*trust.PolicyBundle
	_ = json.NewDecoder(propResp.Body).Decode(&proposals)

	var targetProp *trust.PolicyBundle
	for _, p := range proposals {
		if p.ProposalID == *proposalID {
			targetProp = p
			break
		}
	}

	if targetProp == nil {
		fmt.Printf("Proposal %q not found in authority\n", *proposalID)
		os.Exit(ExitBadArgs)
	}

	// Recompute exact domain-separated signing hash
	signingDigest := trust.ComputePolicySigningDigest(targetProp.TenantID, targetProp.Epoch, targetProp.BundleDigest)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, signingDigest[:])
	if err != nil {
		fmt.Printf("Failed to sign: %v\n", err)
		os.Exit(ExitSigFailed)
	}

	asn1Sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		fmt.Printf("Failed to encode signature: %v\n", err)
		os.Exit(ExitSigFailed)
	}

	payload := map[string]any{
		"proposal_id": *proposalID,
		"actor_id":    *actorID,
		"signature":   hex.EncodeToString(asn1Sig),
	}
	body, _ := json.Marshal(payload)
	signResp, err := http.Post(*authURL+"/api/v1/authority/bundle/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to submit signature: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = signResp.Body.Close() }()

	resBytes, _ := io.ReadAll(signResp.Body)
	if signResp.StatusCode != http.StatusOK {
		fmt.Printf("Signature rejected (HTTP %d): %s\n", signResp.StatusCode, string(resBytes))
		os.Exit(ExitSigFailed)
	}

	fmt.Printf("Signature recorded successfully for %s on proposal %s\n", *actorID, *proposalID)
}

func runPolicyActivate(args []string) {
	fs := flag.NewFlagSet("policy-activate", flag.ExitOnError)
	proposalID := fs.String("proposal", "", "Proposal ID to activate")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *proposalID == "" {
		fmt.Println("Error: --proposal is required")
		os.Exit(ExitBadArgs)
	}

	payload := map[string]any{"proposal_id": *proposalID}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(*authURL+"/api/v1/authority/bundle/activate", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	resBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Activation failed (HTTP %d): %s\n", resp.StatusCode, string(resBytes))
		os.Exit(ExitQuorum)
	}

	fmt.Printf("Bundle activated successfully: %s\n", string(resBytes))
}

func runPolicyStatus(args []string) {
	fs := flag.NewFlagSet("policy-status", flag.ExitOnError)
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	resp, err := http.Get(*authURL + "/api/v1/authority/bundle/active")
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	resBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Failed to get active bundle (HTTP %d): %s\n", resp.StatusCode, string(resBytes))
		os.Exit(ExitBadArgs)
	}
	fmt.Printf("Active Policy Bundle:\n%s\n", string(resBytes))
}

func runPolicyList(args []string) {
	fs := flag.NewFlagSet("policy-list", flag.ExitOnError)
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	resp, err := http.Get(*authURL + "/api/v1/authority/bundle/proposals")
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	resBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Policy Proposals:\n%s\n", string(resBytes))
}

func runRegistryList(args []string) {
	fs := flag.NewFlagSet("registry-list", flag.ExitOnError)
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	resp, err := http.Get(*authURL + "/api/v1/authority/registry")
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	resBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Current Approver Registry:\n%s\n", string(resBytes))
}

func runRegistryPropose(args []string) {
	fs := flag.NewFlagSet("registry-propose", flag.ExitOnError)
	tenant := fs.String("tenant", "tenant-exchange-demo", "Tenant ID")
	m := fs.Int("m", 2, "Proposed threshold M")
	membersFile := fs.String("members-file", "", "JSON file containing proposed Authority members")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *membersFile == "" {
		fmt.Println("Error: --members-file is required")
		os.Exit(ExitBadArgs)
	}

	data, err := os.ReadFile(*membersFile)
	if err != nil {
		fmt.Printf("Failed to read members file: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	var members []struct {
		ActorID     string `json:"actor_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"`
		IsActive    bool   `json:"is_active"`
	}
	if err := json.Unmarshal(data, &members); err != nil {
		fmt.Printf("Invalid members JSON: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	payload := map[string]any{
		"tenant_id":  *tenant,
		"proposed_m": *m,
		"proposed_n": len(members),
		"members":    members,
	}

	body, _ := json.Marshal(payload)
	resp, err := http.Post(*authURL+"/api/v1/authority/registry/propose", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	resBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Registry proposal failed (HTTP %d): %s\n", resp.StatusCode, string(resBytes))
		os.Exit(ExitBadArgs)
	}

	fmt.Printf("Registry proposal submitted: %s\n", string(resBytes))
}

func runRegistrySign(args []string) {
	fs := flag.NewFlagSet("registry-sign", flag.ExitOnError)
	proposalID := fs.String("proposal", "", "Registry proposal ID")
	actorID := fs.String("actor", "", "Signer Actor ID (must be active in CURRENT epoch)")
	keyFile := fs.String("key-file", "", "Signer private key PEM")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *proposalID == "" || *actorID == "" || *keyFile == "" {
		fmt.Println("Error: --proposal, --actor, and --key-file are required")
		os.Exit(ExitBadArgs)
	}

	privKey, err := parsePrivateKey(*keyFile)
	if err != nil {
		fmt.Printf("Failed to parse private key: %v\n", err)
		os.Exit(ExitBadArgs)
	}

	// Fetch proposals to get details for domain-separated hash
	propResp, err := http.Get(fmt.Sprintf("%s/api/v1/authority/registry/proposals", *authURL))
	if err != nil {
		fmt.Printf("Failed to query registry proposals: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = propResp.Body.Close() }()

	var proposals []*trust.RegistryProposal
	_ = json.NewDecoder(propResp.Body).Decode(&proposals)

	var targetProp *trust.RegistryProposal
	for _, p := range proposals {
		if p.ProposalID == *proposalID {
			targetProp = p
			break
		}
	}

	if targetProp == nil {
		fmt.Printf("Registry proposal %q not found\n", *proposalID)
		os.Exit(ExitBadArgs)
	}

	signingDigest := trust.ComputeRegistrySigningDigest(targetProp.TenantID, targetProp.CurrentEpoch, targetProp.TargetEpoch, targetProp.ProposalDigest)

	r, s, err := ecdsa.Sign(rand.Reader, privKey, signingDigest[:])
	if err != nil {
		fmt.Printf("Failed to sign: %v\n", err)
		os.Exit(ExitSigFailed)
	}

	asn1Sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		fmt.Printf("Failed to encode signature: %v\n", err)
		os.Exit(ExitSigFailed)
	}

	payload := map[string]any{
		"proposal_id": *proposalID,
		"actor_id":    *actorID,
		"signature":   hex.EncodeToString(asn1Sig),
	}
	body, _ := json.Marshal(payload)
	signResp, err := http.Post(*authURL+"/api/v1/authority/registry/sign", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to submit signature: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = signResp.Body.Close() }()

	resBytes, _ := io.ReadAll(signResp.Body)
	if signResp.StatusCode != http.StatusOK {
		fmt.Printf("Signature rejected (HTTP %d): %s\n", signResp.StatusCode, string(resBytes))
		os.Exit(ExitSigFailed)
	}

	fmt.Printf("Registry proposal signature recorded for %s\n", *actorID)
}

func runRegistryActivate(args []string) {
	fs := flag.NewFlagSet("registry-activate", flag.ExitOnError)
	proposalID := fs.String("proposal", "", "Registry proposal ID")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *proposalID == "" {
		fmt.Println("Error: --proposal is required")
		os.Exit(ExitBadArgs)
	}

	payload := map[string]any{"proposal_id": *proposalID}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(*authURL+"/api/v1/authority/registry/activate", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	resBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Registry activation failed (HTTP %d): %s\n", resp.StatusCode, string(resBytes))
		os.Exit(ExitQuorum)
	}

	fmt.Printf("Registry successfully activated to new epoch: %s\n", string(resBytes))
}

func runRegistryHistory(args []string) {
	fs := flag.NewFlagSet("registry-history", flag.ExitOnError)
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	resp, err := http.Get(*authURL + "/api/v1/authority/registry/history")
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(ExitBadArgs)
	}
	defer func() { _ = resp.Body.Close() }()

	resBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Registry Epoch History:\n%s\n", string(resBytes))
}

func parsePrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", keyPath)
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return privKey, nil
	}

	pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err2 == nil {
		if ecKey, ok := pkcs8Key.(*ecdsa.PrivateKey); ok {
			return ecKey, nil
		}
	}
	return nil, fmt.Errorf("key must be ECDSA (errors: %v / %v)", err, err2)
}


func runAuditVerify(args []string) {
	os.Exit(executeAuditVerify(args, os.Stdout, os.Stderr))
}

func executeAuditVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	exportFile := fs.String("export-file", "", "Path to the exported audit bundle JSON file (required)")
	genesisFile := fs.String("genesis-file", "", "Path to the pinned Genesis JSON file (optional)")
	expectedTip := fs.String("expected-tip", "", "Expected chain tip digest in hexadecimal (optional)")
	expectedCheckpoint := fs.String("expected-checkpoint", "", "Expected checkpoint digest in hexadecimal (optional)")
	jsonOutput := fs.Bool("json", false, "Output verification report in JSON format")
	if err := fs.Parse(args); err != nil {
		return ExitBadArgs
	}

	if *exportFile == "" {
		fmt.Fprintln(stderr, "Error: --export-file is required")
		return ExitBadArgs
	}

	bundleBytes, err := os.ReadFile(*exportFile)
	if err != nil {
		fmt.Fprintf(stderr, "Failed to read export bundle file %s: %v\n", *exportFile, err)
		return ExitBadArgs
	}

	var bundle audit.AuditExportBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		fmt.Fprintf(stderr, "Invalid export bundle JSON: %v\n", err)
		return ExitBadArgs
	}

	var opts audit.VerifyOptions

	if *genesisFile != "" {
		genBytes, err := os.ReadFile(*genesisFile)
		if err != nil {
			fmt.Fprintf(stderr, "Failed to read genesis file %s: %v\n", *genesisFile, err)
			return ExitBadArgs
		}
		var pinnedGen trust.GenesisState
		if err := json.Unmarshal(genBytes, &pinnedGen); err != nil {
			fmt.Fprintf(stderr, "Invalid genesis JSON: %v\n", err)
			return ExitBadArgs
		}
		opts.PinnedGenesis = &pinnedGen
	}

	if *expectedTip != "" {
		tipD, err := ports.DigestFromHex(*expectedTip)
		if err != nil {
			fmt.Fprintf(stderr, "Invalid --expected-tip hex digest: %v\n", err)
			return ExitBadArgs
		}
		opts.ExpectedTipDigest = &tipD
	}

	if *expectedCheckpoint != "" {
		chkD, err := ports.DigestFromHex(*expectedCheckpoint)
		if err != nil {
			fmt.Fprintf(stderr, "Invalid --expected-checkpoint hex digest: %v\n", err)
			return ExitBadArgs
		}
		opts.ExpectedCheckpointDigest = &chkD
	}

	verifier := audit.NewOfflineVerifier()
	report, err := verifier.VerifyBundle(&bundle, opts)
	if err != nil {
		fmt.Fprintf(stderr, "Verifier error: %v\n", err)
		return ExitSigFailed
	}

	if *jsonOutput {
		out, _ := json.MarshalIndent(report, "", "  ")
		fmt.Fprintln(stdout, string(out))
	} else {
		fmt.Fprint(stdout, audit.FormatReportText(report))
	}

	if !report.Valid {
		for _, e := range report.Errors {
			if containsInsensitive(e, "insufficient signatures") || containsInsensitive(e, "quorum") {
				return ExitQuorum
			}
		}
		return ExitSigFailed
	}

	return ExitSuccess
}

func containsInsensitive(s, substr string) bool {
	return bytes.Contains([]byte(bytes.ToLower([]byte(s))), []byte(bytes.ToLower([]byte(substr))))
}

