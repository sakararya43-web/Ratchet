package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/sakararya43-web/Ratchet/internal/graph"
	v1 "github.com/sakararya43-web/Ratchet/proto/ratchet/v1"
	"github.com/sakararya43-web/Ratchet/proto/ratchet/v1/ratchetv1connect"
)

// Reader is server-configured service identity. The TLS certificate is verified
// by net/http before its CommonName is mapped to an authorized tenant.
type Reader struct {
	TenantID string `json:"tenant_id"`
	ActorID  string `json:"actor_id"`
}
type readerContextKey struct{}
type GraphAPI struct {
	registry  *graph.Registry
	cursorKey []byte
}

func NewGraphHandler(registry *graph.Registry, cursorKey []byte, readers map[string]Reader) (http.Handler, error) {
	if registry == nil || len(cursorKey) != 32 || len(readers) == 0 {
		return nil, errors.New("graph API requires registry, cursor key and authenticated readers")
	}
	acl := map[string]Reader{}
	for name, reader := range readers {
		if name == "" || reader.TenantID == "" || reader.ActorID == "" {
			return nil, errors.New("invalid reader binding")
		}
		acl[name] = reader
	}
	mux := graphRoutes(registry, cursorKey)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
			http.Error(w, "verified client certificate required", http.StatusUnauthorized)
			return
		}
		reader, ok := acl[r.TLS.PeerCertificates[0].Subject.CommonName]
		if !ok {
			http.Error(w, "reader not authorized", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), readerContextKey{}, reader)))
	}), nil
}

func graphRoutes(registry *graph.Registry, key []byte) http.Handler {
	a := &GraphAPI{registry: registry, cursorKey: append([]byte(nil), key...)}
	mux := http.NewServeMux()
	options := []connect.HandlerOption{connect.WithReadMaxBytes(1 << 20), connect.WithSendMaxBytes(8 << 20)}
	p, h := ratchetv1connect.NewGraphServiceHandler(a, options...)
	mux.Handle(p, h)
	p, h = ratchetv1connect.NewImpactServiceHandler(a, options...)
	mux.Handle(p, h)
	return mux
}
func NewSessionGraphHandler(registry *graph.Registry, key []byte, authorize func(context.Context, Principal, string) error) (http.Handler, error) {
	if registry == nil || len(key) != 32 || authorize == nil {
		return nil, errors.New("graph session dependencies required")
	}
	routes := graphRoutes(registry, key)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := SessionPrincipal(r.Context())
		if !ok {
			http.Error(w, "session required", http.StatusUnauthorized)
			return
		}
		operation := "view"
		if strings.Contains(r.URL.Path, "ImpactService") {
			operation = "simulate"
		}
		if err := authorize(r.Context(), p, operation); err != nil {
			http.Error(w, "graph authorization unavailable", http.StatusForbidden)
			return
		}
		routes.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), readerContextKey{}, Reader(p))))
	}), nil
}

func (a *GraphAPI) snapshot(ctx context.Context, tenant string, minVersion int64) (*graph.Snapshot, error) {
	reader, ok := ctx.Value(readerContextKey{}).(Reader)
	if !ok {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("authenticated reader required"))
	}
	if reader.TenantID != tenant {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("tenant identity mismatch"))
	}
	s, err := a.registry.Get(ctx, tenant, minVersion)
	return s, rpcError(err)
}
func rpcError(err error) error {
	if err == nil {
		return nil
	}
	code := connect.CodeInternal
	switch {
	case errors.Is(err, graph.ErrInvalid):
		code = connect.CodeInvalidArgument
	case errors.Is(err, graph.ErrNotFound):
		code = connect.CodeNotFound
	case errors.Is(err, graph.ErrUnavailable):
		code = connect.CodeUnavailable
	case errors.Is(err, graph.ErrAnalysisLimit):
		code = connect.CodeResourceExhausted
	case errors.Is(err, context.Canceled):
		code = connect.CodeCanceled
	case errors.Is(err, context.DeadlineExceeded):
		code = connect.CodeDeadlineExceeded
	}
	return connect.NewError(code, err)
}
func node(n graph.Node) *v1.GraphNode {
	return &v1.GraphNode{Id: n.ID, Type: n.Type, Tier: int32(n.Tier), DisplayName: n.DisplayName, Properties: n.Properties}
}
func edge(e graph.Edge) *v1.GraphEdge {
	props := map[string]string{}
	for k, v := range e.Properties {
		props[k] = v
	}
	props["edge_id"] = e.ID
	return &v1.GraphEdge{Source: e.Source, Target: e.Target, Kind: e.Kind, Action: e.Action, Properties: props}
}
func route(r graph.Route) *v1.GraphRoute {
	return &v1.GraphRoute{NodeIds: r.NodeIDs, EdgeKinds: r.EdgeKinds, EdgeIds: r.EdgeIDs}
}
func resource(n graph.Node) *v1.ResourceSummary {
	return &v1.ResourceSummary{Id: n.ID, Type: n.Type, Tier: int32(n.Tier), DisplayName: n.DisplayName}
}
func safeguard(n graph.Node) *v1.SafeguardSummary {
	return &v1.SafeguardSummary{Id: n.ID, Tier: int32(n.Tier), Description: "protection or control weakened"}
}

type cursor struct {
	Tenant  string `json:"tenant"`
	Scope   string `json:"scope"`
	Version int64  `json:"version"`
	Offset  int    `json:"offset"`
}

func (a *GraphAPI) page(token, tenant, scope string, version int64, total int, size int32) (int, int, string, error) {
	if size == 0 {
		size = 50
	}
	if size < 1 || size > 200 {
		return 0, 0, "", connect.NewError(connect.CodeInvalidArgument, errors.New("page size must be between 1 and 200"))
	}
	offset := 0
	if token != "" {
		parts := strings.Split(token, ".")
		if len(parts) != 2 {
			return 0, 0, "", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid cursor"))
		}
		raw, err := base64.RawURLEncoding.DecodeString(parts[0])
		sig, err2 := base64.RawURLEncoding.DecodeString(parts[1])
		mac := hmac.New(sha256.New, a.cursorKey)
		_, _ = mac.Write(raw)
		var c cursor
		if err != nil || err2 != nil || !hmac.Equal(mac.Sum(nil), sig) || json.Unmarshal(raw, &c) != nil || c.Tenant != tenant || c.Scope != scope || c.Offset < 0 || c.Offset > total {
			return 0, 0, "", connect.NewError(connect.CodeInvalidArgument, errors.New("invalid cursor"))
		}
		if c.Version != version {
			return 0, 0, "", connect.NewError(connect.CodeFailedPrecondition, errors.New("graph context changed; restart pagination"))
		}
		offset = c.Offset
	}
	end := min(offset+int(size), total)
	next := ""
	if end < total {
		raw, _ := json.Marshal(cursor{tenant, scope, version, end})
		mac := hmac.New(sha256.New, a.cursorKey)
		_, _ = mac.Write(raw)
		next = base64.RawURLEncoding.EncodeToString(raw) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return offset, end, next, nil
}

func (a *GraphAPI) GetNodeDetails(ctx context.Context, r *connect.Request[v1.GetNodeDetailsRequest]) (*connect.Response[v1.GetNodeDetailsResponse], error) {
	s, err := a.snapshot(ctx, r.Msg.TenantId, r.Msg.MinGraphVersion)
	if err != nil {
		return nil, err
	}
	n, err := s.Node(r.Msg.NodeId)
	if err != nil {
		return nil, rpcError(err)
	}
	in, out, err := s.IncidentEdges(n.ID)
	if err != nil {
		return nil, rpcError(err)
	}
	if len(in)+len(out) > 1000 {
		return nil, rpcError(graph.ErrAnalysisLimit)
	}
	result := &v1.GetNodeDetailsResponse{Node: node(n), GraphVersion: s.Version()}
	for _, e := range in {
		result.IncomingEdges = append(result.IncomingEdges, edge(e))
	}
	for _, e := range out {
		result.OutgoingEdges = append(result.OutgoingEdges, edge(e))
	}
	return connect.NewResponse(result), nil
}
func (a *GraphAPI) GetNeighbourhood(ctx context.Context, r *connect.Request[v1.GetNeighbourhoodRequest]) (*connect.Response[v1.GetNeighbourhoodResponse], error) {
	s, err := a.snapshot(ctx, r.Msg.TenantId, r.Msg.MinGraphVersion)
	if err != nil {
		return nil, err
	}
	d, truncated, err := s.Neighbourhood(r.Msg.NodeId, int(r.Msg.Depth), 1000)
	if err != nil {
		return nil, rpcError(err)
	}
	start, end, next, err := a.page(r.Msg.PageToken, r.Msg.TenantId, fmt.Sprintf("neighbourhood:%s:%d", r.Msg.NodeId, r.Msg.Depth), s.Version(), len(d.Nodes), r.Msg.PageSize)
	if err != nil {
		return nil, err
	}
	result := &v1.GetNeighbourhoodResponse{GraphVersion: s.Version(), NextPageToken: next, Truncated: truncated}
	ids := map[string]bool{}
	for _, n := range d.Nodes[start:end] {
		result.Nodes = append(result.Nodes, node(n))
		ids[n.ID] = true
	}
	for _, e := range d.Edges {
		if ids[e.Source] {
			result.Edges = append(result.Edges, edge(e))
		}
	}
	return connect.NewResponse(result), nil
}
func (a *GraphAPI) GetReach(ctx context.Context, r *connect.Request[v1.GetReachRequest]) (*connect.Response[v1.GetReachResponse], error) {
	s, err := a.snapshot(ctx, r.Msg.TenantId, r.Msg.MinGraphVersion)
	if err != nil {
		return nil, err
	}
	reach, err := s.Reach(r.Msg.IdentityId)
	if err != nil {
		return nil, rpcError(err)
	}
	start, end, next, err := a.page(r.Msg.PageToken, r.Msg.TenantId, "reach:"+r.Msg.IdentityId, s.Version(), len(reach.Nodes), r.Msg.PageSize)
	if err != nil {
		return nil, err
	}
	result := &v1.GetReachResponse{GraphVersion: s.Version(), NextPageToken: next, ReachByTier: map[string]int32{}}
	ids := map[string]bool{}
	for _, n := range reach.Nodes[start:end] {
		ids[n.ID] = true
		result.ReachableNodes = append(result.ReachableNodes, node(n))
		if slices.Contains(reach.Controlled, n.ID) {
			result.ControlledIdentities = append(result.ControlledIdentities, n.ID)
		}
	}
	for _, p := range reach.Powers {
		if ids[p.NodeID] {
			result.Powers = append(result.Powers, &v1.AccessPower{NodeId: p.NodeID, Action: p.Action})
		}
	}
	for tier, count := range reach.ByTier {
		result.ReachByTier[fmt.Sprint(tier)] = int32(count)
	}
	return connect.NewResponse(result), nil
}
func (a *GraphAPI) GetPathsToCritical(ctx context.Context, r *connect.Request[v1.GetPathsToCriticalRequest]) (*connect.Response[v1.GetPathsToCriticalResponse], error) {
	s, err := a.snapshot(ctx, r.Msg.TenantId, r.Msg.MinGraphVersion)
	if err != nil {
		return nil, err
	}
	paths, err := s.PathsTo(r.Msg.IdentityId, 1000, 100000)
	if err != nil {
		return nil, rpcError(err)
	}
	start, end, next, err := a.page(r.Msg.PageToken, r.Msg.TenantId, "paths:"+r.Msg.IdentityId, s.Version(), len(paths.Routes), r.Msg.MaxPaths)
	if err != nil {
		return nil, err
	}
	result := &v1.GetPathsToCriticalResponse{GraphVersion: s.Version(), NextPageToken: next, Truncated: paths.Truncated}
	for _, p := range paths.Routes[start:end] {
		result.Routes = append(result.Routes, route(p))
	}
	return connect.NewResponse(result), nil
}
func (a *GraphAPI) SimulateChange(ctx context.Context, r *connect.Request[v1.SimulateChangeRequest]) (*connect.Response[v1.SimulateChangeResponse], error) {
	s, err := a.snapshot(ctx, r.Msg.TenantId, r.Msg.MinGraphVersion)
	if err != nil {
		return nil, err
	}
	kind, target, access := r.Msg.Kind, r.Msg.TargetIdentity, r.Msg.RequestedAccess
	if intent := r.Msg.Intent; intent != nil {
		switch intent.Kind {
		case v1.ChangeKind_CHANGE_KIND_ROLE_ASSIGN:
			kind = "ROLE_ASSIGN"
		case v1.ChangeKind_CHANGE_KIND_ROLE_REVOKE:
			kind = "ROLE_REVOKE"
		case v1.ChangeKind_CHANGE_KIND_MODIFY_SAFEGUARD:
			kind = "MODIFY_SAFEGUARD"
		default:
			return nil, rpcError(graph.ErrInvalid)
		}
		target, access = intent.TargetIdentity, intent.RequestedAccess
	}
	reader := ctx.Value(readerContextKey{}).(Reader)
	if r.Msg.RequestedBy != "" && r.Msg.RequestedBy != reader.ActorID {
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("requester identity mismatch"))
	}
	var d graph.Delta
	if r.Msg.Intent != nil && kind == "MODIFY_SAFEGUARD" && len(r.Msg.Intent.SafeguardParameters) > 0 {
		d, err = s.EditSafeguard(target, r.Msg.Intent.SafeguardParameters)
	} else {
		d, err = s.Draft(kind, target, access)
	}
	if err != nil {
		return nil, rpcError(err)
	}
	impact, err := s.ImpactDiff(d)
	if err != nil {
		return nil, rpcError(err)
	}
	result := &v1.ImpactDiff{GraphVersion: impact.Version, MonotonicReduction: impact.MonotonicReduction, BlastRadiusDelta: map[string]int32{}}
	resources, controlled := map[string]bool{}, map[string]bool{}
	for _, n := range impact.Weakened {
		result.SafeguardsWeakened = append(result.SafeguardsWeakened, safeguard(n))
	}
	for _, item := range impact.Affected {
		i := &v1.IdentityImpact{IdentityId: item.IdentityID, BlastRadiusDelta: map[string]int32{}}
		for _, n := range item.NewResources {
			i.NewResources = append(i.NewResources, resource(n))
			if !resources[n.ID] {
				resources[n.ID] = true
				result.NewResources = append(result.NewResources, resource(n))
			}
		}
		for _, id := range item.NewControlled {
			i.NewControlledIdentities = append(i.NewControlledIdentities, id)
			if !controlled[id] {
				controlled[id] = true
				result.NewControlledIdentities = append(result.NewControlledIdentities, id)
			}
		}
		for _, p := range item.NewPowers {
			i.NewPowers = append(i.NewPowers, &v1.AccessPower{NodeId: p.NodeID, Action: p.Action})
		}
		for _, p := range item.RemovedPowers {
			i.RemovedPowers = append(i.RemovedPowers, &v1.AccessPower{NodeId: p.NodeID, Action: p.Action})
		}
		i.RemovedControlledIdentities = item.RemovedControlled
		for _, p := range item.NewRoutes {
			i.NewTier0Routes = append(i.NewTier0Routes, route(p))
			result.SampleTier0Routes = append(result.SampleTier0Routes, route(p))
			result.NewTier0PathsCount++
		}
		for _, n := range item.Weakened {
			i.SafeguardsWeakened = append(i.SafeguardsWeakened, safeguard(n))
		}
		for tier, count := range item.BlastDelta {
			i.BlastRadiusDelta[fmt.Sprint(tier)] = int32(count)
			result.BlastRadiusDelta[fmt.Sprint(tier)] += int32(count)
		}
		result.AffectedIdentities = append(result.AffectedIdentities, i)
	}
	return connect.NewResponse(&v1.SimulateChangeResponse{Impact: result}), nil
}
