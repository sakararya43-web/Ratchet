package graph

import "context"

type flowEdge struct {
	to, reverse int
	capacity    int64
}
type flowNetwork struct{ edges [][]flowEdge }
type flowArc struct{ from, index, action int }

func newFlow(n int) *flowNetwork { return &flowNetwork{edges: make([][]flowEdge, n)} }
func (f *flowNetwork) add(from, to int, capacity int64) int {
	index := len(f.edges[from])
	reverse := len(f.edges[to])
	// Self loops are unnecessary for connectivity and would complicate reverse
	// indexing; callers omit them when translating raw authority edges.
	f.edges[from] = append(f.edges[from], flowEdge{to, reverse, capacity})
	f.edges[to] = append(f.edges[to], flowEdge{from, index, 0})
	return index
}
func (f *flowNetwork) cut(ctx context.Context, source, sink int, limit int64) (int64, []bool, error) {
	var total int64
	for total < limit {
		if err := ctx.Err(); err != nil {
			return 0, nil, err
		}
		level := make([]int, len(f.edges))
		for i := range level {
			level[i] = -1
		}
		level[source] = 0
		queue := []int{source}
		for at := 0; at < len(queue); at++ {
			for _, e := range f.edges[queue[at]] {
				if e.capacity > 0 && level[e.to] < 0 {
					level[e.to] = level[queue[at]] + 1
					queue = append(queue, e.to)
				}
			}
		}
		if level[sink] < 0 {
			seen := make([]bool, len(level))
			for i, v := range level {
				seen[i] = v >= 0
			}
			return total, seen, nil
		}
		next := make([]int, len(f.edges))
		work := 0
		var push func(int, int64) (int64, error)
		push = func(node int, amount int64) (int64, error) {
			work++
			if work%1024 == 0 {
				if err := ctx.Err(); err != nil {
					return 0, err
				}
			}
			if node == sink {
				return amount, nil
			}
			for next[node] < len(f.edges[node]) {
				index := next[node]
				e := f.edges[node][index]
				if e.capacity > 0 && level[e.to] == level[node]+1 {
					sent, err := push(e.to, min(amount, e.capacity))
					if err != nil {
						return 0, err
					}
					if sent > 0 {
						f.edges[node][index].capacity -= sent
						f.edges[e.to][e.reverse].capacity += sent
						return sent, nil
					}
				}
				next[node]++
			}
			return 0, nil
		}
		for total < limit {
			sent, err := push(source, limit-total)
			if err != nil {
				return 0, nil, err
			}
			if sent == 0 {
				break
			}
			total += sent
		}
	}
	return total, nil, nil
}
