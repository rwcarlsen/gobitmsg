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
		Ip:       "127.0.0.1",
		Port:     8444,
	}

	var vr *p2p.VerResp
	go func() {
		vr = <- node.Ver
	}()

	err := node.VersionExchange(peeraddr)
	if err != nil {
		log.Print(err)
		if vr == nil {
			return
		}
	}

	log.Printf("Other Version: %+v", *vr.OtherVer)

	for _, addr := range vr.OtherPeers[:min(10, len(vr.OtherPeers))] {
		log.Printf("received info on peer %+v", *addr)
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
