package main

import (
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
		Ip:       "127.0.0.1",
		Port:     19840,
	}

	peeraddr := &payload.AddressInfo{
		Time:     tm,
		Stream:   1,
		Services: 1,
		Ip:       "127.0.0.1",
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



	vr, err := VersionExchange("127.0.0.1:8444", vmsg, []*payload.AddressInfo{}, [][]byte{})
	if err != nil {
		log.Fatal(err)
	}

	for _, addr := range vr.OtherPeers {
		log.Printf("received info on peer %v:%v", addr.Ip, addr.Port)
	}

	for _, hash := range vr.OtherInv {
		log.Printf("received inventory hash %x", hash)
	}
}

type VerResp struct {
	OtherVer *payload.Version
	OtherPeers	[]*payload.AddressInfo
	OtherInv [][]byte
}

func VersionExchange(addr string, v *payload.Version, ai []*payload.AddressInfo, inv [][]byte) (vr *VerResp, err error) {
	defer logRecover()

	conn, err := p2p.Dial(addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	vr = &VerResp{}

	// send version msg and wait for verack
	m := msg.New(msg.Cversion, v.Encode())
	conn.Write(m.Encode())

	msg.Must(msg.ReadKind(conn, msg.Cverack))

	// wait for version message and send verack
	m = msg.Must(msg.ReadKind(conn, msg.Cversion))
	vr.OtherVer, err = payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}

	conn.Write(msg.New(msg.Cverack, []byte{}).Encode())

	// send addr and inv messages
	am := msg.New(msg.Caddr, payload.AddrEncode(ai...))
	conn.Write(am.Encode())

	im := msg.New(msg.Cinv, payload.InventoryEncode(inv))
	conn.Write(im.Encode())

	// wait for addr and inv messages
	m = msg.Must(msg.ReadKind(conn, msg.Caddr))
	vr.OtherPeers, err = payload.AddrDecode(m.Payload())
	if err != nil {
		panic(err)
	}

	m = msg.Must(msg.ReadKind(conn, msg.Cinv))
	vr.OtherInv, err = payload.InventoryDecode(m.Payload())
	if err != nil {
		panic(err)
	}

	return vr, nil
}

func logRecover() {
	if r := recover(); r != nil {
		log.Print(r)
	}
}

