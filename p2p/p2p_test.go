package p2p

import (
	"bytes"
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

func TestSendAndRespond(t *testing.T) {
	node := NewNode("127.0.0.1:22334", &RecvHandler{})
	if err := node.Start(); err != nil {
		t.Fatalf("node failed to start: %v", err)
	}

	m := msg.New(msg.Cversion, []byte("hello from node1"))
	conn, err := Dial("127.0.0.1:22334")
	if err != nil {
		t.Errorf("connection to peer node failed:", err)
	}
	defer conn.Close()

	conn.Write(m.Encode())
	resp, err := msg.Decode(conn)
	if err != nil {
		t.Errorf("response from peer node failed:", err)
	}

	if !bytes.Equal(m.Payload(), resp.Payload()) {
		t.Errorf("echo response failed: expected %s, got %s", m.Payload(), resp.Payload())
	}
}
