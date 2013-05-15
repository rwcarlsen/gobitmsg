package p2p

import (
	"bytes"
	"net"
	"testing"

	"github.com/rwcarlsen/gobitmsg/msg"
)

type SendHandler struct {
	Resp *msg.Msg
}

func (h *SendHandler) Handle(conn net.Conn) {
	m, err := msg.Decode(conn)
	if err != nil {
		return
	}

	h.Resp = m
	conn.Close()
}

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
	h := &SendHandler{}
	if err := Send("127.0.0.1:22334", m, h); err != nil {
		t.Errorf("send to peer node failed:", err)
	} else if !bytes.Equal(m.Payload(), h.Resp.Payload()) {
		t.Errorf("echo response failed: expected %s, got %s", m.Payload(), h.Resp.Payload())
	}
}
