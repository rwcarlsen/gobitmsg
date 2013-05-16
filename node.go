package main

import (
	"fmt"
	"log"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
	"github.com/rwcarlsen/gobitmsg/p2p"
	"github.com/rwcarlsen/gobitmsg/payload"
)

func main() {
	tm := time.Now()

	myaddr := &payload.AddressInfo{
		Time:     tm,
		Stream:   1,
		Services: 1,
		Ip:       "68.119.167.210",
		Port:     19840,
	}

	peer := "85.5.66.52:8444"
	peeraddr := &payload.AddressInfo{
		Time:     tm,
		Stream:   1,
		Services: 1,
		Ip:       "85.5.66.52",
		Port:     8444,
	}

	vmsg := &payload.Version{
		Services:  1,
		Timestamp: tm,
		ToAddr:    peeraddr,
		FromAddr:  myaddr,
		UserAgent: "Go bitmessage Daemon",
		Streams:   []int{1},
	}

	vr, err := VersionExchange(peer, vmsg, []*payload.AddressInfo{}, [][]byte{})
	if err != nil {
		log.Print(err)
		if vr == nil {
			log.Fatal()
		}
	}

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
