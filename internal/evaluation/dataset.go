package evaluation

import (
	"fmt"

	"github.com/sakararya43-web/Ratchet/internal/graph"
)

// LargeGraph has exactly 100,000 edges: 1,000 principals, 1,000 shared roles,
// 20,000 resources, inherited access and forty controller dependencies.
func LargeGraph() graph.Data {
	d := graph.Data{}
	for i := range 1000 {
		kind := "Human"
		if i >= 800 {
			kind = "ServiceAccount"
		}
		d.Nodes = append(d.Nodes, graph.Node{ID: fmt.Sprintf("principal:%d", i), Type: kind}, graph.Node{ID: fmt.Sprintf("role:%d", i), Type: "Role"})
		for j := range 10 {
			d.Edges = append(d.Edges, graph.Edge{ID: fmt.Sprintf("assignment:%d:%d", i, j), Source: fmt.Sprintf("principal:%d", i), Target: fmt.Sprintf("role:%d", (i*7+j*13)%1000), Kind: "ASSIGNED"})
		}
		for j := range 90 {
			if i < 40 && j == 89 {
				continue
			}
			d.Edges = append(d.Edges, graph.Edge{ID: fmt.Sprintf("grant:%d:%d", i, j), Source: fmt.Sprintf("role:%d", i), Target: fmt.Sprintf("resource:%d", (i*89+j)%20000), Kind: "GRANTS", Action: "read"})
		}
	}
	for i := range 20000 {
		tier := 2
		if i%200 == 0 {
			tier = 0
		}
		d.Nodes = append(d.Nodes, graph.Node{ID: fmt.Sprintf("resource:%d", i), Type: "Resource", Tier: tier})
	}
	for i := range 40 {
		d.Edges = append(d.Edges, graph.Edge{ID: fmt.Sprintf("control:%d", i), Source: fmt.Sprintf("principal:%d", 960+i), Target: fmt.Sprintf("principal:%d", i), Kind: "CAN_ASSUME"})
	}
	return d
}
