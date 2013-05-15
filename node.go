package main

import (
	"log"
	"time"
	"net"

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



	addrs, inv, err := VersionExchange("127.0.0.1:8444", vmsg, []*payload.AddressInfo{}, [][]byte{})
	if err != nil {
		log.Fatal(err)
	}

	for _, addr := range addrs {
		log.Printf("received info on peer %v:%v", addr.Ip, addr.Port)
	}

	for _, hash := range inv {
		log.Printf("received inventory hash %x", hash)
	}
}

func VersionExchange(addr string, v *payload.Version, ai []*payload.AddressInfo, inv [][]byte) (nai []*payload.AddressInfo, ninv [][]byte, err error) {
	h := &VersionHandler {
		CurrPeers: ai,
		CurrInventory: inv,
	}

	m := msg.New(msg.Cversion, v.Encode())
	if err := p2p.Send(addr, m, h); err != nil {
		return nil, nil, err
	}

	return h.CurrPeers, h.CurrInventory, nil
}

func logRecover() {
	if r := recover(); r != nil {
		log.Print(r)
	}
}

// handler for dealing with a sequence of sends/receives initiated by us
// sending a version message to another peer.
type VersionHandler struct {
	NewPeers []*payload.AddressInfo
	NewInventory [][]byte
	CurrPeers []*payload.AddressInfo
	CurrInventory [][]byte
	Ver *payload.Version
}

func (h *VersionHandler) Handle(conn net.Conn) {
	defer logRecover()
	defer conn.Close()

	// wait for verack
	msg.Must(msg.ReadKind(conn, msg.Cverack))

	// wait for version message and send verack
	m := msg.Must(msg.ReadKind(conn, msg.Cversion))
	h.recvVer(m)

	conn.Write(msg.New(msg.Cverack, []byte{}).Encode())

	// send addr and inv messages
	am := msg.New(msg.Caddr, payload.AddrEncode(h.CurrPeers...))
	conn.Write(am.Encode())

	im := msg.New(msg.Cinv, payload.InventoryEncode(h.CurrInventory))
	conn.Write(im.Encode())

	// wait for addr and inv messages
	m = msg.Must(msg.ReadKind(conn, msg.Caddr))
	h.recvPeers(m)

	m = msg.Must(msg.ReadKind(conn, msg.Cinv))
	h.recvInv(m)
}

func (h *VersionHandler) recvVer(m *msg.Msg) {
	ver, err := payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}
	h.Ver = ver
}

func (h *VersionHandler) recvPeers(m *msg.Msg) {
	addrs, err := payload.AddrDecode(m.Payload())
	if err != nil {
		panic(err)
	}
	h.NewPeers = addrs
}

func (h *VersionHandler) recvInv(m *msg.Msg) {
	hashes, err := payload.InventoryDecode(m.Payload())
	if err != nil {
		panic(err)
	}
	h.NewInventory = hashes
}

