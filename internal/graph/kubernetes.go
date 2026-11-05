package graph

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"strings"

	kube "github.com/sakararya43-web/Ratchet/internal/domain/kubernetes"
)

const kubeFuture = "$ratchet-future"

func KubernetesNodeID(cluster, kind, key string) string {
	d := sha256.Sum256([]byte(cluster + "\x00" + kind + "\x00" + key))
	return "k8s:" + kind + ":" + hex.EncodeToString(d[:])
}

type kubeView struct {
	object kube.Object
	scope  string
	rules  []kube.Rule
	exists bool
}

func kubeWitness(states []kube.State) string {
	future := kubeFuture
	for {
		collision := false
		for _, state := range states {
			raw, _ := json.Marshal(state)
			if strings.Contains(string(raw), future) {
				collision = true
				break
			}
		}
		if !collision {
			return future
		}
		future += "x"
	}
}

func kubeViews(state kube.State) (map[string]kubeView, error) {
	resolved, err := state.RoleRules()
	if err != nil {
		return nil, err
	}
	views := map[string]kubeView{}
	definitions := map[string]kube.Object{}
	for _, object := range state.Objects {
		if object.Kind == "Role" || object.Kind == "ClusterRole" {
			definitions[kube.ObjectKey(object)] = object
		}
	}
	add := func(role kube.Object, scope string) {
		key := KubernetesNodeID(state.Cluster, "role", kube.ObjectKey(role)+"\x00"+scope)
		definition, exists := definitions[kube.ObjectKey(role)]
		if exists {
			role = definition
		}
		views[key] = kubeView{object: role, scope: scope, rules: resolved[kube.ObjectKey(role)], exists: exists}
	}
	// Creating a new privileged role must not disappear from analysis merely
	// because its name has not been observed yet. Include a fresh-name witness
	// and literal names mentioned by role constraints. These views carry no
	// observed grants; only the combined create/bind/escalate closure can use them.
	names := map[string]bool{kubeWitness([]kube.State{state}) + "-role": true}
	for _, object := range state.Objects {
		for _, r := range object.Rules {
			if slices.Contains(r.APIGroups, kube.RBACGroup) || slices.Contains(r.APIGroups, "*") {
				for _, name := range r.ResourceNames {
					if len(name) <= 253 && !strings.ContainsAny(name, "/ \t\r\n*") {
						names[name] = true
					}
				}
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		clusterRole := kube.Object{Kind: "ClusterRole", Name: name}
		if _, exists := definitions[kube.ObjectKey(clusterRole)]; !exists {
			add(clusterRole, "")
			for _, ns := range state.Namespaces {
				add(clusterRole, ns)
			}
		}
		for _, ns := range state.Namespaces {
			role := kube.Object{Kind: "Role", Name: name, Namespace: ns}
			if _, exists := definitions[kube.ObjectKey(role)]; !exists {
				add(role, ns)
			}
		}
		if len(views) > 8192 {
			return nil, ErrAnalysisLimit
		}
	}
	for _, object := range state.Objects {
		switch object.Kind {
		case "Role":
			add(object, object.Namespace)
		case "ClusterRole":
			add(object, "")
			for _, ns := range state.Namespaces {
				add(object, ns)
			}
		case "RoleBinding", "ClusterRoleBinding":
			role := kube.Object{Kind: object.RoleKind, Name: object.RoleName}
			if role.Kind == "Role" {
				role.Namespace = object.Namespace
			}
			add(role, object.Namespace)
		}
	}
	if len(views) > 8192 {
		return nil, ErrAnalysisLimit
	}
	return views, nil
}

func scopedRules(view kubeView) []kube.ScopedRule {
	out := make([]kube.ScopedRule, len(view.rules))
	for i, r := range view.rules {
		out[i] = kube.ScopedRule{Namespace: view.scope, Rule: r}
	}
	return out
}

func wildRules(scope string) []kube.ScopedRule {
	return []kube.ScopedRule{{Namespace: scope, Rule: kube.Rule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}}, {Namespace: scope, Rule: kube.Rule{Verbs: []string{"*"}, NonResourceURLs: []string{"*"}}}}
}

func kubeResourceScope(state kube.State, group, resource string) (bool, bool) {
	for _, discovery := range state.Resources {
		if discovery.Group == group && discovery.Resource == resource {
			return discovery.Namespaced, true
		}
	}
	if group == kube.RBACGroup {
		switch resource {
		case "roles", "rolebindings":
			return true, true
		case "clusterroles", "clusterrolebindings":
			return false, true
		}
	}
	if group == "" {
		switch resource {
		case "users", "groups":
			return false, true
		case "serviceaccounts", "serviceaccounts/token":
			return true, true
		}
	}
	return false, false
}

// kubeAtoms retains symbolic future capabilities for wildcards. Comparison uses
// a common basis from both states, so narrowing '*' cannot look like an increase
// merely because a concrete permission was not materialized in the old graph.
func kubeAtoms(states []kube.State) (map[string]kube.Permission, error) {
	// Symbolic witnesses must not equal a literal name in either state. A
	// fixed sentinel could otherwise misclassify named-to-unbounded authority
	// as a reduction when a real principal/resource happened to use that name.
	future := kubeWitness(states)
	atoms := map[string]kube.Permission{}
	add := func(p kube.Permission) error {
		raw, _ := json.Marshal(p)
		atoms[string(raw)] = p
		if len(atoms) > 100000 {
			return ErrAnalysisLimit
		}
		return nil
	}
	for _, state := range states {
		if err := state.Validate(); err != nil {
			return nil, err
		}
		views, err := kubeViews(state)
		if err != nil {
			return nil, err
		}
		// Keep future capabilities even when a cluster currently has no roles.
		// They are required for system:masters and for edit+escalate closure.
		views["future-global"] = kubeView{}
		for _, ns := range state.Namespaces {
			views["future-"+ns] = kubeView{scope: ns}
		}
		// Concrete probes complement symbolic wildcard atoms. Otherwise a role
		// with only '*' could hide its ability to bind a named role or mint a
		// specific service account's token in graph and policy evidence.
		for _, p := range state.Principals {
			resource, ns := "users", ""
			if p.Kind == "ServiceAccount" {
				resource, ns = "serviceaccounts", p.Namespace
			}
			if err := add(kube.Permission{Resource: resource, Namespace: ns, Name: p.Name, Verb: "impersonate"}); err != nil {
				return nil, err
			}
			if p.Kind == "ServiceAccount" {
				if err := add(kube.Permission{Resource: resource, Subresource: "token", Namespace: ns, Name: p.Name, Verb: "create"}); err != nil {
					return nil, err
				}
			}
		}
		for _, view := range views {
			if view.object.Kind == "" {
				continue
			}
			resource := "roles"
			if view.object.Kind == "ClusterRole" {
				resource = "clusterroles"
			}
			for _, verb := range []string{"bind", "escalate", "update", "patch", "create"} {
				ns := view.object.Namespace
				if verb == "bind" {
					ns = view.scope
				}
				name := view.object.Name
				if verb == "create" {
					name = ""
				}
				if err := add(kube.Permission{APIGroup: kube.RBACGroup, Resource: resource, Verb: verb, Namespace: ns, Name: name}); err != nil {
					return nil, err
				}
			}
		}
		for _, view := range views {
			rules := append(scopedRules(view), wildRules(view.scope)...)
			for _, scoped := range rules {
				r := scoped.Rule
				for _, verb := range r.Verbs {
					if verb == "*" {
						verb = future + "-verb"
					}
					for _, url := range r.NonResourceURLs {
						if scoped.Namespace != "" {
							continue
						}
						if url == "*" {
							url = "/" + future
						}
						if strings.HasSuffix(url, "*") {
							url = strings.TrimSuffix(url, "*") + kubeFuture
						}
						if err := add(kube.Permission{Verb: verb, NonResourceURL: url}); err != nil {
							return nil, err
						}
					}
					for _, group := range r.APIGroups {
						for _, resource := range r.Resources {
							if group == "*" {
								group = future + "-group"
							}
							if resource == "*" {
								resource = future + "-resource"
							}
							resource = strings.Replace(resource, "*/", future+"-resource/", 1)
							parts := strings.SplitN(resource, "/", 2)
							sub := ""
							if len(parts) == 2 {
								sub = parts[1]
							}
							if sub == "*" {
								continue
							} // Not a Kubernetes resource glob.
							names := r.ResourceNames
							if len(names) == 0 {
								names = []string{future + "-name"}
							}
							scopes := []string{scoped.Namespace}
							namespaced, known := kubeResourceScope(state, group, resource)
							namespacedBind := group == kube.RBACGroup && resource == "clusterroles" && verb == "bind"
							if scoped.Namespace != "" && known && !namespaced && !namespacedBind {
								continue
							}
							if scoped.Namespace == "" {
								if namespaced || !known {
									scopes = append(append([]string(nil), state.Namespaces...), future+"-namespace")
									if !known {
										scopes = append(scopes, "")
									}
								}
							}
							for _, ns := range scopes {
								for _, name := range names {
									if (verb == "create" && sub == "") || verb == "deletecollection" {
										name = ""
									}
									p := kube.Permission{APIGroup: group, Resource: parts[0], Subresource: sub, Verb: verb, Namespace: ns, Name: name}
									if err := add(p); err != nil {
										return nil, err
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return atoms, nil
}

func kubeTier(p kube.Permission) int {
	if strings.HasPrefix(p.APIGroup, kubeFuture) || strings.HasPrefix(p.Resource, kubeFuture) || strings.HasPrefix(p.Verb, kubeFuture) || strings.HasPrefix(p.Namespace, kubeFuture) || strings.Contains(p.NonResourceURL, kubeFuture) {
		return 0
	}
	if p.Verb == "bind" || p.Verb == "escalate" || p.Verb == "impersonate" || (p.Resource == "serviceaccounts" && p.Subresource == "token" && p.Verb == "create") {
		return 0
	}
	if p.Resource == "secrets" && slices.Contains([]string{"get", "list", "watch"}, p.Verb) {
		return 0
	}
	if p.Resource == "pods" && slices.Contains([]string{"exec", "attach", "ephemeralcontainers"}, p.Subresource) {
		return 0
	}
	if p.APIGroup == kube.RBACGroup && slices.Contains([]string{"create", "update", "patch", "delete", "deletecollection"}, p.Verb) {
		return 0
	}
	return 2
}

// CompileKubernetes projects normalized real observations into the same immutable
// graph used by the simulator. The bounded fixed point includes token takeover,
// impersonation, bind plus binding-write permission, and edit plus escalate.
// It does not fetch/parse API objects or introduce an alternative write path.
func CompileKubernetes(version int64, state kube.State, comparison ...kube.State) (*Snapshot, error) {
	if err := state.Validate(); err != nil {
		return nil, err
	}
	states := append([]kube.State{state}, comparison...)
	atoms, err := kubeAtoms(states)
	if err != nil {
		return nil, err
	}
	views, err := kubeViews(state)
	if err != nil {
		return nil, err
	}
	nodes := map[string]Node{}
	edges := map[string]Edge{}
	addEdge := func(source, target, kind, provenance string) bool {
		id := KubernetesNodeID(state.Cluster, "edge", source+"\x00"+target+"\x00"+kind+"\x00"+provenance)
		if _, exists := edges[id]; exists {
			return false
		}
		edges[id] = Edge{ID: id, Source: source, Target: target, Kind: kind}
		return true
	}
	principals := map[string]kube.Principal{}
	subjects := map[string]string{}
	for _, p := range state.Principals {
		id := KubernetesNodeID(state.Cluster, "identity", p.ID)
		principals[id] = p
		subjects[kube.PrincipalKey(p.Kind, p.Namespace, p.Name)] = id
		kind := "Human"
		if p.Kind == "ServiceAccount" {
			kind = "ServiceAccount"
		}
		nodes[id] = Node{ID: id, Type: kind}
		for _, group := range kube.PrincipalGroups(p) {
			gid := KubernetesNodeID(state.Cluster, "group", group)
			nodes[gid] = Node{ID: gid, Type: "Group"}
			addEdge(id, gid, "MEMBER_OF", "observed-group")
		}
	}
	for signature, p := range atoms {
		id := KubernetesNodeID(state.Cluster, "permission", signature)
		nodes[id] = Node{ID: id, Type: "Resource", Tier: kubeTier(p)}
	}
	atomKeys := slices.Sorted(maps.Keys(atoms))
	work := 0
	grantView := func(id string, view kubeView) error {
		nodes[id] = Node{ID: id, Type: "Role"}
		for _, signature := range atomKeys {
			p := atoms[signature]
			work += len(view.rules)
			if work > 10_000_000 {
				return ErrAnalysisLimit
			}
			allowed, err := kube.Allows(scopedRules(view), p)
			if err != nil {
				return err
			}
			if !allowed {
				continue
			}
			target := KubernetesNodeID(state.Cluster, "permission", signature)
			edge := Edge{Source: id, Target: target, Kind: "GRANTS", Action: p.Verb}
			edge.ID = KubernetesNodeID(state.Cluster, "edge", id+"\x00"+target+"\x00"+p.Verb)
			edges[edge.ID] = edge
		}
		return nil
	}
	for _, id := range slices.Sorted(maps.Keys(views)) {
		view := views[id]
		if err := grantView(id, view); err != nil {
			return nil, err
		}
	}
	for id, p := range principals {
		if slices.Contains(kube.PrincipalGroups(p), "system:masters") {
			mid := KubernetesNodeID(state.Cluster, "role", "system:masters-bypass")
			rules := wildRules("")
			view := kubeView{}
			for _, r := range rules {
				view.rules = append(view.rules, r.Rule)
			}
			views[mid] = view
			if err := grantView(mid, view); err != nil {
				return nil, err
			}
			addEdge(id, mid, "ASSIGNED", "system:masters")
		}
	}
	bindingView := func(binding kube.Object) string {
		role := kube.Object{Kind: binding.RoleKind, Name: binding.RoleName}
		if role.Kind == "Role" {
			role.Namespace = binding.Namespace
		}
		return KubernetesNodeID(state.Cluster, "role", kube.ObjectKey(role)+"\x00"+binding.Namespace)
	}
	for _, binding := range state.Objects {
		if binding.Kind != "RoleBinding" && binding.Kind != "ClusterRoleBinding" {
			continue
		}
		view := bindingView(binding)
		for _, subject := range binding.Subjects {
			source := subjects[kube.PrincipalKey(subject.Kind, subject.Namespace, subject.Name)]
			if subject.Kind == "Group" {
				source = KubernetesNodeID(state.Cluster, "group", subject.Name)
				nodes[source] = Node{ID: source, Type: "Group"}
			}
			if source == "" {
				return nil, kube.ErrInvalid
			}
			addEdge(source, view, "ASSIGNED", binding.UID+":"+kube.SubjectKey(subject))
		}
	}
	build := func() (*Snapshot, error) {
		data := Data{Nodes: make([]Node, 0, len(nodes)), Edges: make([]Edge, 0, len(edges))}
		for _, n := range nodes {
			data.Nodes = append(data.Nodes, n)
		}
		for _, e := range edges {
			data.Edges = append(data.Edges, e)
		}
		return Build(version, data)
	}
	for round := 0; round < 64; round++ {
		compiled, err := build()
		if err != nil {
			return nil, err
		}
		changed := false
		for _, id := range slices.Sorted(maps.Keys(principals)) {
			reach, err := compiled.Reach(id)
			if err != nil {
				return nil, err
			}
			rules := []kube.ScopedRule{}
			reachable := map[string]bool{}
			for _, node := range reach.Nodes {
				if view, ok := views[node.ID]; ok {
					rules = append(rules, scopedRules(view)...)
					reachable[node.ID] = true
				}
			}
			var permissionError error
			has := func(permission kube.Permission) bool {
				work += len(rules)
				if work > 10_000_000 {
					return false
				}
				allowed, err := kube.Allows(rules, permission)
				if err != nil {
					permissionError = err
				}
				return err == nil && allowed
			}
			canImpersonateUser := false
			for _, r := range rules {
				for _, name := range append([]string{kubeFuture + "-user"}, r.Rule.ResourceNames...) {
					if has(kube.Permission{Resource: "users", Verb: "impersonate", Name: name}) {
						canImpersonateUser = true
					}
				}
			}
			if canImpersonateUser && has(kube.Permission{Resource: "groups", Verb: "impersonate", Name: "system:masters"}) {
				mid := KubernetesNodeID(state.Cluster, "role", "impersonated-system:masters")
				if _, ok := views[mid]; !ok {
					v := kubeView{}
					for _, r := range wildRules("") {
						v.rules = append(v.rules, r.Rule)
					}
					views[mid] = v
					if err := grantView(mid, v); err != nil {
						return nil, err
					}
				}
				changed = addEdge(id, mid, "ASSIGNED", "impersonated-system:masters") || changed
			}
			for _, target := range slices.Sorted(maps.Keys(principals)) {
				q := principals[target]
				if id == target {
					continue
				}
				if q.Kind == "ServiceAccount" && has(kube.Permission{Resource: "serviceaccounts", Subresource: "token", Verb: "create", Namespace: q.Namespace, Name: q.Name}) {
					changed = addEdge(id, target, "CAN_ASSUME", "token-request") || changed
				}
				resource := "users"
				namespace := ""
				if q.Kind == "ServiceAccount" {
					resource = "serviceaccounts"
					namespace = q.Namespace
				}
				if !has(kube.Permission{Resource: resource, Verb: "impersonate", Namespace: namespace, Name: q.Name}) {
					continue
				}
				for _, binding := range state.Objects {
					if binding.Kind != "RoleBinding" && binding.Kind != "ClusterRoleBinding" {
						continue
					}
					match := false
					for _, sub := range binding.Subjects {
						if sub.Kind == q.Kind && sub.Name == q.Name && sub.Namespace == q.Namespace {
							match = true
						}
						if sub.Kind == "Group" && (sub.Name == "system:authenticated" || (q.Kind == "ServiceAccount" && slices.Contains(kube.PrincipalGroups(q), sub.Name)) || has(kube.Permission{Resource: "groups", Verb: "impersonate", Name: sub.Name})) {
							match = true
						}
					}
					if match {
						changed = addEdge(id, bindingView(binding), "ASSIGNED", "impersonate:"+q.ID+":"+binding.UID) || changed
					}
				}
			}
			if canImpersonateUser {
				for _, binding := range state.Objects {
					if binding.Kind != "RoleBinding" && binding.Kind != "ClusterRoleBinding" {
						continue
					}
					for _, sub := range binding.Subjects {
						if sub.Kind == "Group" && has(kube.Permission{Resource: "groups", Verb: "impersonate", Name: sub.Name}) {
							changed = addEdge(id, bindingView(binding), "ASSIGNED", "impersonate-group:"+binding.UID) || changed
						}
					}
				}
			}
			for _, viewID := range slices.Sorted(maps.Keys(views)) {
				view := views[viewID]
				if view.object.Kind == "" {
					continue
				}
				resource := "roles"
				if view.object.Kind == "ClusterRole" {
					resource = "clusterroles"
				}
				bound := view.scope != "" || view.object.Kind == "ClusterRole"
				bindingResource := "rolebindings"
				if view.scope == "" {
					bindingResource = "clusterrolebindings"
				}
				write := has(kube.Permission{APIGroup: kube.RBACGroup, Resource: bindingResource, Verb: "create", Namespace: view.scope})
				for _, binding := range state.Objects {
					if binding.Namespace == view.scope && bindingView(binding) == viewID {
						write = write || has(kube.Permission{APIGroup: kube.RBACGroup, Resource: bindingResource, Verb: "update", Namespace: view.scope, Name: binding.Name}) || has(kube.Permission{APIGroup: kube.RBACGroup, Resource: bindingResource, Verb: "patch", Namespace: view.scope, Name: binding.Name})
					}
				}
				bind := has(kube.Permission{APIGroup: kube.RBACGroup, Resource: resource, Verb: "bind", Namespace: view.scope, Name: view.object.Name})
				if !bind {
					work += len(rules) * len(view.rules)
					if work > 10_000_000 {
						return nil, ErrAnalysisLimit
					}
					covered, err := kube.Covers(rules, scopedRules(view))
					if err != nil {
						return nil, err
					}
					bind = covered
				}
				if bound && write && bind {
					changed = addEdge(id, viewID, "ASSIGNED", "potential-bind") || changed
				}
				edit := has(kube.Permission{APIGroup: kube.RBACGroup, Resource: resource, Verb: "update", Namespace: view.object.Namespace, Name: view.object.Name}) || has(kube.Permission{APIGroup: kube.RBACGroup, Resource: resource, Verb: "patch", Namespace: view.object.Namespace, Name: view.object.Name})
				if !view.exists {
					edit = has(kube.Permission{APIGroup: kube.RBACGroup, Resource: resource, Verb: "create", Namespace: view.object.Namespace})
				}
				if reachable[viewID] && edit && has(kube.Permission{APIGroup: kube.RBACGroup, Resource: resource, Verb: "escalate", Namespace: view.object.Namespace, Name: view.object.Name}) {
					escalated := KubernetesNodeID(state.Cluster, "role", "escalate:"+viewID)
					if _, exists := views[escalated]; !exists {
						v := kubeView{scope: view.scope}
						for _, r := range wildRules(view.scope) {
							v.rules = append(v.rules, r.Rule)
						}
						views[escalated] = v
						if err := grantView(escalated, v); err != nil {
							return nil, err
						}
					}
					changed = addEdge(id, escalated, "ASSIGNED", "potential-escalate") || changed
				}
			}
			if permissionError != nil {
				return nil, permissionError
			}
			if work > 10_000_000 {
				return nil, ErrAnalysisLimit
			}
		}
		if !changed {
			return compiled, nil
		}
	}
	return nil, ErrAnalysisLimit
}

// KubernetesImpact compares the complete affected identity graph, including
// existing group bindings and potential privilege paths, on a common universe.
func KubernetesImpact(version int64, before kube.State, mutation kube.Mutation) (Impact, error) {
	after, err := before.After(mutation)
	if err != nil {
		return Impact{}, err
	}
	a, err := CompileKubernetes(version, before, after)
	if err != nil {
		return Impact{}, err
	}
	b, err := CompileKubernetes(version, after, before)
	if err != nil {
		return Impact{}, err
	}
	delta := snapshotDifference(a, b)
	return a.ImpactDiff(delta)
}

func snapshotDifference(before, after *Snapshot) Delta {
	d := Delta{}
	oldNodes := map[string]Node{}
	newNodes := map[string]Node{}
	oldEdges := map[string]Edge{}
	newEdges := map[string]Edge{}
	for _, n := range before.nodes {
		oldNodes[n.ID] = n
	}
	for _, n := range after.nodes {
		newNodes[n.ID] = n
		if old, ok := oldNodes[n.ID]; !ok || !reflect.DeepEqual(old, n) {
			d.NodesAdded = append(d.NodesAdded, n)
		}
	}
	for _, n := range before.nodes {
		if _, ok := newNodes[n.ID]; !ok {
			d.NodesRemoved = append(d.NodesRemoved, n.ID)
		}
	}
	for _, e := range before.edges {
		oldEdges[e.ID] = e
	}
	for _, e := range after.edges {
		newEdges[e.ID] = e
		if old, ok := oldEdges[e.ID]; !ok {
			d.EdgesAdded = append(d.EdgesAdded, e)
		} else if !reflect.DeepEqual(old, e) {
			d.EdgesRemoved = append(d.EdgesRemoved, e.ID)
			d.EdgesAdded = append(d.EdgesAdded, e)
		}
	}
	for _, e := range before.edges {
		if _, ok := newEdges[e.ID]; !ok {
			d.EdgesRemoved = append(d.EdgesRemoved, e.ID)
		}
	}
	return d
}
