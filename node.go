package main

import (
	"log"
	"os"
	"time"

	"github.com/rwcarlsen/gobitmsg/p2p"
	"github.com/rwcarlsen/gobitmsg/payload"
)

func main() {
	lg := log.New(os.Stdout, "", log.LstdFlags)
	node := p2p.NewNode("127.0.0.1", 19840, lg)
	if err := node.Start(); err != nil {
		log.Fatal(err)
	}

	peeraddr := &payload.AddressInfo{
		Time:     time.Now(),
		Stream:   1,
		Services: 1,
		Ip:       "127.0.0.1",
		Port:     8444,
	}

	node.VersionExchange(peeraddr)
	resp := <-node.VerIn

	log.Printf("Other Version: %+v", *resp.Ver)

	for _, addr := range resp.Peers[:min(10, len(resp.Peers))] {
		log.Printf("received info on peer %+v", *addr)
	}

	for _, hash := range resp.Inv[:min(10, len(resp.Inv))] {
		log.Printf("received inventory hash %x", hash)
	}
}

func min(x, y int) int {
	if x < y {
		return x
	}
	return y
}
