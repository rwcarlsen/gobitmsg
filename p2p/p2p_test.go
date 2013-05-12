package p2p

import (
	"bytes"
	"testing"
	"io"

	"github.com/rwcarlsen/gobitmsg/msg"
)

type TestHandler struct {}

func (h *TestHandler) Handle(w io.Writer, m *msg.Msg) {
	w.Write(m.Encode())
}

func TestSendAndRespond(t *testing.T) {
	node1 := NewNode("127.0.0.1:22334", &TestHandler{})
	if err := node1.ListenAndServe(); err != nil {
		t.Fatalf("node1 failed to start: %v", err)
	}

	node2 := NewNode("127.0.0.1:22335", &TestHandler{})
	if err := node2.ListenAndServe(); err != nil {
		t.Fatalf("node2 failed to start: %v", err)
	}

	m := msg.New(msg.Cversion, []byte("hello from node1"))
	resp, err := Send(node2.Addr(), m)
	if  err != nil {
		t.Errorf("node1 -> node2 send failed: %v", err)
	} else if !bytes.Equal(m.Payload(), resp.Payload()) {
		t.Errorf("node2 -> node1 response failed: expected %s, got %s", m.Payload(), resp.Payload())
	}
}
