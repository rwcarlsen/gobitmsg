package p2p

import (
	"net"
	"testing"
	"log"
	"os"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
	"github.com/rwcarlsen/gobitmsg/payload"
)

type RecvHandler struct{}

func (h *RecvHandler) Handle(conn net.Conn) {
	m, err := msg.Decode(conn)
	if err != nil {
		return
	}
	conn.Write(m.Encode())
}

func newTestNode(name string, ip string, port int) *Node {
	addr := &payload.AddressInfo{
		Time:     time.Now(),
		Stream:   1,
		Services: 1,
		Ip:       ip,
		Port:     port,
	}
	ver := &payload.Version{
		Services:  1,
		Timestamp: time.Now(),
		ToAddr:    addr,
		FromAddr:  addr,
		UserAgent: "Go bitmessage Daemon",
		Streams:   []int{1},
	}
	return &Node{
		Addr: addr.Addr(),
		Log: log.New(os.Stdout, name + ": ", log.LstdFlags),
		Objects: make(chan *msg.Msg),
		Ver: make(chan *VerResp),
		MyVer: ver,
		MyAddrList: []*payload.AddressInfo{},
		MyInvList: [][]byte{},
	}
}

func TestVersionExchange(t *testing.T) {
	node1 := newTestNode("node1", "127.0.0.1", 22334)
	if err := node1.Start(); err != nil {
		t.Fatalf("node1 failed to start: %v", err)
	}

	node2 := newTestNode("node2", "127.0.0.1", 22335)
	if err := node2.Start(); err != nil {
		t.Fatalf("node2 failed to start: %v", err)
	}

	go func() {
		<- node1.Ver
	}()

	err = node1.VersionExchange(node2.MyVer.FromAddr)
	if err != nil {
		t.Fatal(err)
	}
}
