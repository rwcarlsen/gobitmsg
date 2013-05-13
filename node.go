
package main

import (
	"io"
	"log"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
	"github.com/rwcarlsen/gobitmsg/payload"
	"github.com/rwcarlsen/gobitmsg/p2p"
)

func main() {
	tm := time.Now()

	myaddr := &payload.AddressInfo{
		Time: tm,
		Stream: 1,
		Services: 1,
		Ip: "128.104.186.18",
		Port: 19840,
	}

	peeraddr := &payload.AddressInfo{
		Time: tm,
		Stream: 1,
		Services: 1,
		Ip: "127.0.0.1",
		Port: 8444,
	}

	vmsg := &payload.Version{
		Services: 1,
		Timestamp: tm,
		ToAddr: peeraddr,
		FromAddr: myaddr,
		UserAgent: "Go bitmessage Daemon",
		Streams: []int{1},
	}

	m := msg.New(msg.Cversion, vmsg.Encode())

	//node := p2p.NewNode("127.0.0.1:19840", &RecvHandler{})
	//if err := node.Start(); err != nil {
	//	log.Fatalf("node failed to start: %v", err)
	//}

	p := p2p.NewPeer("98.28.255.178:8444")
	if err := p.Send(m, &SendHandler{}); err != nil {
		log.Fatalf("message send failed: %v", err)
	}
}

type RecvHandler struct {}

func (h *RecvHandler) Handle(w io.WriteCloser, m *msg.Msg) {
	log.Printf("received unexpected connection of type %v", m.Cmd())
}

type SendHandler struct {}

func (h *SendHandler) Handle(w io.WriteCloser, m *msg.Msg) {
	log.Printf("received msg from peer of type %v", m.Cmd())
	switch cmd := m.Cmd(); cmd {
	case msg.Cverack:
	case msg.Cversion:
		w.Write(msg.New(msg.Cverack, []byte{}).Encode())
	case msg.Caddr:
	case msg.Cinv:
		log.Printf("communication complete", cmd)
		w.Close()
	default:
		log.Printf("msg type %v from peer is unanticipated", cmd)

	}
}

//	m := msg.New(msg.Cversion, v.Encode())
//	if _, err := conn.Write(m.Encode()); err != nil {
//		return nil, err
//	}
//
//	// receive verack
//	resp, err := msg.Decode(conn)
//	if err != nil {
//		return nil, err
//	} else if resp.Cmd() != msg.Cverack {
//		return nil, fmt.Errorf("Expected msg type %v, got %v",
//			msg.Cverack, resp.Cmd())
//	}
//
//	// receive version response
//	resp, err := msg.Decode(conn)
//	if err != nil {
//		return nil, err
//	} else if resp.Cmd() != msg.Cversion {
//		return nil, fmt.Errorf("Expected msg type %v, got %v",
//			msg.Cversion, resp.Cmd())
//	}
//
//	v, err = payload.VersionDecode(resp.Payload())
//	if err != nil {
//		return nil, fmt.Errorf("Failed to decode version response: %v", err)
//	}
//
//	// send verack
//	conn.Write(msg.New(msg.Cverack, []byte{}).Encode())
//	return v, nil

