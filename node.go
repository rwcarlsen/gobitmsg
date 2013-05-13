
package main

import (
	"io"
	"log"

	"github.com/rwcarlsen/gobitmsg/msg"
	"github.com/rwcarlsen/gobitmsg/payload"
	"github.com/rwcarlsen/gobitmsg/p2p"
)

func main() {
	node := p2p.NewNode("127.0.0.1:19840", &TestHandler{})
	if err := node.Start(); err != nil {
		log.Fatalf("node failed to start: %v", err)
	}

	tm := payload.FuzzyTime(payload.DefaultFuzz)

	myaddr := &payload.AddressInfo{
		Time: tm,
		Stream: 1,
		Services: 0,
		Ip: "68.119.167.210",
		Port: 19840,
	}

	peeraddr := &payload.AddressInfo{
		Time: tm,
		Stream: 1,
		Services: 0,
		Ip: "98.28.255.178",
		Port: 8444,
	}

	vmsg := &payload.Version{
		Services: 0,
		Timestamp: tm,
		ToAddr: peeraddr,
		FromAddr: myaddr,
		UserAgent: "Go bitmessage Daemon",
		Streams: []int{1},
	}

	m := msg.New(msg.Cversion, vmsg.Encode())

	resp, err := p2p.Send("127.0.0.1:8444", m)
	if err != nil {
		log.Fatalf("message send failed: %v", err)
	}

	log.Printf("received response of type %v", resp.Cmd())
}

type TestHandler struct {}

func (h *TestHandler) Handle(w io.Writer, m *msg.Msg) {
	log.Printf("received direct msg from peer of type %v", m.Cmd())
}

