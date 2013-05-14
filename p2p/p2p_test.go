package p2p

import (
	"bytes"
	"testing"
	"io"

	"github.com/rwcarlsen/gobitmsg/msg"
)

type SendHandler struct {
	Resp *msg.Msg
}

func (h *SendHandler) Handle(w io.WriteCloser, m *msg.Msg) {
	h.Resp = m
	w.Close()
}

type RecvHandler struct {}

func (h *RecvHandler) Handle(w io.WriteCloser, m *msg.Msg) {
	w.Write(m.Encode())
}

func TestSendAndRespond(t *testing.T) {
	node := NewNode("127.0.0.1:22334", &RecvHandler{})
	if err := node.Start(); err != nil {
		t.Fatalf("node failed to start: %v", err)
	}

	p := NewPeer("127.0.0.1:22334")

	m := msg.New(msg.Cversion, []byte("hello from node1"))
	h := &SendHandler{}
	if err := p.Send(m, h); err != nil {
		t.Errorf("send to peer node failed:", err)
	} else if !bytes.Equal(m.Payload(), h.Resp.Payload()) {
		t.Errorf("echo response failed: expected %s, got %s", m.Payload(), h.Resp.Payload())
	}
}
