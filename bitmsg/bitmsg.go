package bitmsg

const (
	Version = "0.2.7"
)

type NodeSet struct {
	Nodes []*Node
}

func (s *NodeSet) Add(nodes ...*Node) {
	s.Nodes = append(s.Nodes, nodes...)
}

func (s *NodeSet) InStream(stream int) []*Node {
	nodes := make([]*Node, 0)
	for _, n := range s.Nodes {
		if n.Stream == stream {
			nodes = append(nodes, n)
		}
	}
	return nodes
}

type Node struct {
	Stream  int
	Friends *NodeSet
}
