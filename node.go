package main

import (
	"log"
	"time"

	"github.com/rwcarlsen/gobitmsg/p2p"
	"github.com/rwcarlsen/gobitmsg/payload"
)

func main() {
	tm := time.Now()

	node := p2p.NewNode("mynode", "127.0.0.1", 19840)

	peeraddr := &payload.AddressInfo{
		Time:     tm,
		Stream:   1,
		Services: 1,
		Ip:       "66.65.120.151",
		Port:     8080,
	}

	err := node.VersionExchange(peeraddr)
	if err != nil {
		log.Fatal(err)
	}

	vr := <- node.Ver

	for _, addr := range vr.OtherPeers[:min(10, len(vr.OtherPeers))] {
		log.Printf("received info on peer %v:%v", addr.Ip, addr.Port)
	}

	for _, hash := range vr.OtherInv[:min(10, len(vr.OtherInv))] {
		log.Printf("received inventory hash %x", hash)
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
