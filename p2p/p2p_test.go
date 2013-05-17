package p2p

import (
	"net"
	"testing"

	"github.com/rwcarlsen/gobitmsg/msg"
)

type RecvHandler struct{}

func (h *RecvHandler) Handle(conn net.Conn) {
	m, err := msg.Decode(conn)
	if err != nil {
		return
	}
	conn.Write(m.Encode())
}

func TestVersionExchange(t *testing.T) {
	node1 := NewNode("node1", "127.0.0.1", 22334)
	if err := node1.Start(); err != nil {
		t.Fatalf("node1 failed to start: %v", err)
	}

	node2 := NewNode("node2", "127.0.0.1", 22335)
	if err := node2.Start(); err != nil {
		t.Fatalf("node2 failed to start: %v", err)
	}

	go func() {
		<-node1.Ver
	}()

	err := node1.VersionExchange(node2.MyVer.FromAddr)
	if err != nil {
		t.Fatal(err)
	}
}
