package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
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
)

type ecdsaSignature struct {
	R, S *big.Int
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "genesis":
		runGenesis(os.Args[2:])
	case "policy":
		if len(os.Args) < 3 {
			fmt.Println("Usage: ratchetctl policy <propose|sign|activate|status> [flags]")
			os.Exit(1)
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
		default:
			fmt.Printf("Unknown policy subcommand: %s\n", subcmd)
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`ratchetctl — Operational CLI for RATCHET Security Control Plane

Usage:
  ratchetctl genesis --tenant=<id> --m=<threshold> --members-file=<path> [--authority-url=<url>]
  ratchetctl policy propose --bundle-file=<path> --version=<v> [--authority-url=<url>]
  ratchetctl policy sign --proposal=<id> --actor=<actor_id> --key-file=<key.pem> [--authority-url=<url>]
  ratchetctl policy activate --proposal=<id> [--authority-url=<url>]
  ratchetctl policy status [--authority-url=<url>]`)
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
		os.Exit(1)
	}

	data, err := os.ReadFile(*membersFile)
	if err != nil {
		fmt.Printf("Failed to read members file: %v\n", err)
		os.Exit(1)
	}

	var members []struct {
		ActorID     string `json:"actor_id"`
		DisplayName string `json:"display_name"`
		PublicKey   string `json:"public_key"`
	}
	if err := json.Unmarshal(data, &members); err != nil {
		fmt.Printf("Invalid members JSON: %v\n", err)
		os.Exit(1)
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
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Genesis failed (HTTP %d): %s\n", resp.StatusCode, string(respBytes))
		os.Exit(1)
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
		os.Exit(1)
	}

	data, err := os.ReadFile(*bundleFile)
	if err != nil {
		fmt.Printf("Failed to read bundle file: %v\n", err)
		os.Exit(1)
	}

	var bundleContent struct {
		Modules map[string]string `json:"modules"`
		Data    map[string]any    `json:"data"`
	}
	if err := json.Unmarshal(data, &bundleContent); err != nil {
		fmt.Printf("Invalid bundle JSON: %v\n", err)
		os.Exit(1)
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
		os.Exit(1)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		fmt.Printf("Proposal failed (HTTP %d): %s\n", resp.StatusCode, string(respBytes))
		os.Exit(1)
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
		os.Exit(1)
	}

	// Read and parse private key
	keyBytes, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Printf("Failed to read key file: %v\n", err)
		os.Exit(1)
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		fmt.Println("Failed to decode PEM block in key file")
		os.Exit(1)
	}

	privKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			fmt.Printf("Failed to parse private key: %v / %v\n", err, err2)
			os.Exit(1)
		}
		var ok bool
		privKey, ok = pkcs8Key.(*ecdsa.PrivateKey)
		if !ok {
			fmt.Println("Private key must be ECDSA P-256")
			os.Exit(1)
		}
	}

	// Fetch active proposal to get its canonical BundleDigest
	resp, err := http.Get(fmt.Sprintf("%s/api/v1/authority/bundle/active", *authURL))
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Compute signature over proposal digest
	// Sign the proposal
	sigHash := sha256.Sum256([]byte(*proposalID))
	r, s, err := ecdsa.Sign(rand.Reader, privKey, sigHash[:])
	if err != nil {
		fmt.Printf("Failed to sign: %v\n", err)
		os.Exit(1)
	}

	asn1Sig, err := asn1.Marshal(ecdsaSignature{R: r, S: s})
	if err != nil {
		fmt.Printf("Failed to encode signature: %v\n", err)
		os.Exit(1)
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
		os.Exit(1)
	}
	defer signResp.Body.Close()

	resBytes, _ := io.ReadAll(signResp.Body)
	fmt.Printf("Signature result: %s\n", string(resBytes))
}

func runPolicyActivate(args []string) {
	fs := flag.NewFlagSet("policy-activate", flag.ExitOnError)
	proposalID := fs.String("proposal", "", "Proposal ID to activate")
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	if *proposalID == "" {
		fmt.Println("Error: --proposal is required")
		os.Exit(1)
	}

	payload := map[string]any{"proposal_id": *proposalID}
	body, _ := json.Marshal(payload)
	resp, err := http.Post(*authURL+"/api/v1/authority/bundle/activate", "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	resBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Activation failed (HTTP %d): %s\n", resp.StatusCode, string(resBytes))
		os.Exit(1)
	}

	fmt.Printf("Bundle activated: %s\n", string(resBytes))
}

func runPolicyStatus(args []string) {
	fs := flag.NewFlagSet("policy-status", flag.ExitOnError)
	authURL := fs.String("authority-url", "http://localhost:8086", "Authority service URL")
	_ = fs.Parse(args)

	resp, err := http.Get(*authURL + "/api/v1/authority/bundle/active")
	if err != nil {
		fmt.Printf("Failed to contact authority: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	resBytes, _ := io.ReadAll(resp.Body)
	fmt.Printf("Active Policy Bundle:\n%s\n", string(resBytes))
}
