package p2p

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
	"github.com/rwcarlsen/gobitmsg/payload"
)

const (
	defaultTimeout = 4 * time.Second
)

type VerDat struct {
	Ver   *payload.Version
	Peers []*payload.AddressInfo
	Inv   [][]byte
	Err   error
}

type Node struct {
	Addr       string
	Log        *log.Logger
	ObjectsIn  chan *msg.Msg
	objectsOut chan broadcastReq
	VerIn      chan *VerDat
	verOut     chan *payload.AddressInfo
	MyVer      *payload.Version
	MyPeers    []*payload.AddressInfo
	MyInv      map[string][]byte
}

func (n *Node) invList() [][]byte {
	hashes := make([][]byte, 0, len(n.MyInv))
	for s, _ := range n.MyInv {
		sum, _ := hex.DecodeString(s)
		hashes = append(hashes, sum)
	}
	return hashes
}

func NewNode(ip string, port int, lg *log.Logger) *Node {
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
		UserAgent: "/gobitmsg-0.1/",
		Streams:   []int{1},
	}
	return &Node{
		Addr:       addr.Addr(),
		Log:        lg,
		ObjectsIn:  make(chan *msg.Msg),
		objectsOut: make(chan broadcastReq),
		VerIn:      make(chan *VerDat),
		verOut:     make(chan *payload.AddressInfo),
		MyVer:      ver,
		MyPeers:    []*payload.AddressInfo{},
		MyInv:      map[string][]byte{},
	}
}

// Start sets the node to begin listening for and serving messages
// to/from other nodes in daemon mode.  This method does not block and
// returns immediately.
func (n *Node) Start() error {
	ln, err := net.Listen("tcp", n.Addr)
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			go n.handleConn(conn)
		}
	}()

	go func() {
		for {
			addr := <-n.verOut
			n.versionExchange(addr)
		}
	}()

	go func() {
		for {
			req := <-n.objectsOut
			n.broadcastObj(req)
		}
	}()

	return nil
}

func (n *Node) handleConn(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			n.Log.Print(r)
		}
	}()

	defer conn.Close()

	m := msg.Must(msg.Decode(conn))
	n.Log.Printf("Received msg type %v", m.Cmd())

	switch m.Cmd() {
	case msg.Cversion:
		n.versionSequence(m, conn)
	case msg.Cgetdata:
		n.respondGetData(m, conn)
	case msg.CgetpubKey, msg.Cpubkey, msg.Cmsg, msg.Cbroadcast:
		n.ObjectsIn <- m
	default:
		n.Log.Printf("Received unsupported communication %v", m.Cmd())
	}
}

// VersionExchanges initiates and performs a version exchange sequence with
// the node at addr.
func (n *Node) VersionExchange(addr *payload.AddressInfo) {
	n.verOut <- addr
}

func (n *Node) versionExchange(addr *payload.AddressInfo) {
	resp := &VerDat{}
	defer func() { n.VerIn <- resp }()
	defer func() {
		if r := recover(); r != nil {
			resp.Err = fmt.Errorf("[ERR] version exchange did not complete (%v)", r)
			n.Log.Print(resp.Err)
		}
	}()

	n.Log.Printf("[INFO] version exchange with %v", addr.Addr())
	conn, err := net.DialTimeout("tcp", addr.Addr(), defaultTimeout)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	n.verOutVerackIn(conn, addr, payload.ProtocolVersion)

	// wait for version message and send verack
	m := msg.Must(msg.ReadKind(conn, msg.Cversion))
	resp.Ver, err = payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}
	if _, err := conn.Write(msg.New(msg.Cverack, []byte{}).Encode()); err != nil {
		panic(err)
	}

	n.sendInvAndAddr(conn, resp.Ver.Protocol())

	// wait for addr and inv messages
	m = msg.Must(msg.ReadKind(conn, msg.Caddr))
	resp.Peers, err = payload.AddrDecode(resp.Ver.Protocol(), m.Payload())
	if err != nil {
		panic(err)
	}

	m = msg.Must(msg.ReadKind(conn, msg.Cinv))
	resp.Inv, err = payload.InventoryDecode(resp.Ver.Protocol(), m.Payload())
	if err != nil {
		panic(err)
	}

	n.Log.Printf("[INFO] version exchange with %v successful", addr.Addr())
}

func (n *Node) versionSequence(m *msg.Msg, conn net.Conn) {
	resp := &VerDat{}
	defer func() {
		if r := recover(); r != nil {
			resp.Err = fmt.Errorf("[ERR] version sequence did not complete (%v)", r)
			n.Log.Print(resp.Err)
		}
	}()

	var err error
	n.Log.Printf("[INFO] version sequence with %v", conn.RemoteAddr())

	resp.Ver, err = payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}
	defer func() { n.VerIn <- resp }()

	if _, err := conn.Write(msg.New(msg.Cverack, []byte{}).Encode()); err != nil {
		panic(err)
	}

	n.verOutVerackIn(conn, resp.Ver.FromAddr, resp.Ver.Protocol())
	n.sendInvAndAddr(conn, resp.Ver.Protocol())

	// wait for addr and inv messages
	m = msg.Must(msg.ReadKind(conn, msg.Caddr))
	resp.Peers, err = payload.AddrDecode(resp.Ver.Protocol(), m.Payload())
	if err != nil {
		panic(err)
	}

	m = msg.Must(msg.ReadKind(conn, msg.Cinv))
	resp.Inv, err = payload.InventoryDecode(resp.Ver.Protocol(), m.Payload())
	if err != nil {
		panic(err)
	}
	n.Log.Printf("[INFO] version sequence with %v successful", conn.RemoteAddr())
}

func (n *Node) sendInvAndAddr(conn net.Conn, proto uint32) {
	pay, err := payload.AddrEncode(proto, n.MyPeers...)
	if err != nil {
		panic(err)
	}
	am := msg.New(msg.Caddr, pay)
	if _, err := conn.Write(am.Encode()); err != nil {
		panic(err)
	}

	pay, err = payload.InventoryEncode(proto, n.invList())
	if err != nil {
		panic(err)
	}
	im := msg.New(msg.Cinv, pay)
	if _, err := conn.Write(im.Encode()); err != nil {
		panic(err)
	}
}

func (n *Node) verOutVerackIn(conn net.Conn, to *payload.AddressInfo, proto uint32) {
	vcopy := *n.MyVer
	vcopy.Timestamp = time.Now()
	vcopy.ToAddr = to
	pay, err := vcopy.Encode(proto)
	if err != nil {
		panic(err)
	}
	m := msg.New(msg.Cversion, pay)
	if _, err := conn.Write(m.Encode()); err != nil {
		panic(err)
	}
	msg.Must(msg.ReadKind(conn, msg.Cverack))
}

type broadcastReq struct {
	m *msg.Msg
	peers []*payload.Version
}

func (n *Node) Broadcast(m *msg.Msg, peers ...*payload.Version) {
	n.objectsOut <- broadcastReq{m, peers}
}

func (n *Node) broadcastObj(req broadcastReq) {
	for _, p := range req.peers {
		conn, err := net.DialTimeout("tcp", p.FromAddr.Addr(), defaultTimeout)
		if err != nil {
			continue
		}
		conn.Write(req.m.Encode())
		conn.Close()
	}
}

func (n *Node) respondGetData(m *msg.Msg, conn net.Conn) {
	hashes, err := payload.GetDataDecode(payload.ProtocolVersion, m.Payload())
	if err != nil {
		n.Log.Printf("[ERR] failed to decode getdata payload from %v (%v)", conn.RemoteAddr(), err)
		return
	}

	for _, sum := range hashes {
		s := fmt.Sprint("%x", sum)
		if data, ok := n.MyInv[s]; ok {
			if _, err := conn.Write(data); err != nil {
				n.Log.Printf("[ERR] failed to send all requested objects to %v (%v)", conn.RemoteAddr(), err)
				break
			}
		} else {
			n.Log.Printf("[ERR] %v requested object we don't have", conn.RemoteAddr())
		}
	}
	n.Log.Printf("[INFO] sent %v requested objects to %v", len(hashes), conn.RemoteAddr())
}

// GetData retrieves requests objects with the specified hashes from the
// peer node that sent us ver.  It returns the number of objects
// successfully received and an error if n < len(hashes).
func (nd *Node) GetData(ver *payload.Version, hashes [][]byte) (n int, err error) {
	conn, err := net.DialTimeout("tcp", ver.FromAddr.Addr(), defaultTimeout)
	if err != nil {
		return n, err
	}
	defer conn.Close()
	pay, err := payload.GetDataEncode(ver.Protocol(), hashes)
	if err != nil {
		panic(err)
	}
	m := msg.New(msg.Cgetdata, pay)
	conn.Write(m.Encode())

	for i := 0; i < len(hashes); i++ {
		m, err := msg.Decode(conn)
		if err != nil {
			return n, err
		}
		switch m.Cmd() {
		case msg.Cversion, msg.Cverack, msg.Caddr, msg.Cinv, msg.Cgetdata:
			return n, fmt.Errorf("getdata resp contains invalid msg type %v", m.Cmd())
		}
		nd.ObjectsIn <- m
		n++
	}
	return n, nil
}
