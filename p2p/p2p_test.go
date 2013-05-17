package p2p

import (
	"log"
	"net"
	"os"
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
	lg1 := log.New(os.Stdout, "node1: ", log.LstdFlags)
	node1 := NewNode("127.0.0.1", 22334, lg1)
	if err := node1.Start(); err != nil {
		t.Fatalf("node1 failed to start: %v", err)
	}

	lg2 := log.New(os.Stdout, "node2: ", log.LstdFlags)
	node2 := NewNode("127.0.0.1", 22335, lg2)
	if err := node2.Start(); err != nil {
		t.Fatalf("node2 failed to start: %v", err)
	}

	ver := *node1.MyVer
	ver.ToAddr = node2.MyVer.FromAddr

	node1.VersionExchange(node2.MyVer.FromAddr)
	resp := <-node1.VerIn

	t.Logf("response version: %+v", resp.Ver)
}
