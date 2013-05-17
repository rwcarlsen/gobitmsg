package p2p

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
	"github.com/rwcarlsen/gobitmsg/payload"
)

const (
	defaultTimeout = 7 * time.Second
)

func NewNode(name string, ip string, port int) *Node {
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
		Addr:       addr.Addr(),
		Log:        log.New(os.Stdout, name+": ", log.LstdFlags),
		ObjectsIn:  make(chan *msg.Msg),
		objectsOut: make(chan *msg.Msg),
		VerIn:      make(chan *VerDat),
		verOut:     make(chan *VerDat),
		MyVer:      ver,
		MyPeers:    []*payload.AddressInfo{},
		MyInv:      [][]byte{},
	}
}

// dial opens a stream with the peer at addr.
func dial(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, defaultTimeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type VerDat struct {
	Ver   *payload.Version
	Peers []*payload.AddressInfo
	Inv   [][]byte
}

type Node struct {
	Addr       string
	Log        *log.Logger
	ObjectsIn  chan *msg.Msg
	objectsOut chan *msg.Msg
	VerIn      chan *VerDat
	verOut     chan *VerDat
	MyVer      *payload.Version
	MyPeers    []*payload.AddressInfo
	MyInv      [][]byte
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
			n.versionExchange()
		}
	}()

	go func() {
		for {
			n.broadcastObj()
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

func (n *Node) versionSequence(m *msg.Msg, conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			n.Log.Printf("version sequence failed (%v)", r)
		}
	}()

	var err error
	resp := &VerDat{}

	resp.Ver, err = payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}

	defer func() { n.VerIn <- resp }()

	if _, err := conn.Write(msg.New(msg.Cverack, []byte{}).Encode()); err != nil {
		panic(err)
	}

	// send version msg and wait for verack
	vcopy := *n.MyVer
	vcopy.Timestamp = time.Now()
	vcopy.ToAddr = resp.Ver.FromAddr
	m = msg.New(msg.Cversion, vcopy.Encode())
	if _, err := conn.Write(m.Encode()); err != nil {
		panic(err)
	}

	msg.Must(msg.ReadKind(conn, msg.Cverack))

	// send addr and inv messages
	am := msg.New(msg.Caddr, payload.AddrEncode(n.MyPeers...))
	if _, err := conn.Write(am.Encode()); err != nil {
		panic(err)
	}

	im := msg.New(msg.Cinv, payload.InventoryEncode(n.MyInv))
	if _, err := conn.Write(im.Encode()); err != nil {
		panic(err)
	}

	// wait for addr and inv messages
	m = msg.Must(msg.ReadKind(conn, msg.Caddr))
	resp.Peers, err = payload.AddrDecode(m.Payload())
	if err != nil {
		panic(err)
	}

	m = msg.Must(msg.ReadKind(conn, msg.Cinv))
	resp.Inv, err = payload.InventoryDecode(m.Payload())
	if err != nil {
		panic(err)
	}
}

// versionExchanges initiates and performs a version exchange sequence with
// the node at addr.
func (n *Node) versionExchange() {
	defer func() {
		if r := recover(); r != nil {
			n.Log.Printf("version exchange failed (%v)", r)
		}
	}()

	req := <-n.verOut

	n.Log.Printf("Dialing address %v", req.Ver.ToAddr.Addr())
	conn, err := dial(req.Ver.ToAddr.Addr())
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	resp := &VerDat{}

	// send version msg and wait for verack
	m := msg.New(msg.Cversion, req.Ver.Encode())
	if _, err := conn.Write(m.Encode()); err != nil {
		panic(err)
	}

	msg.Must(msg.ReadKind(conn, msg.Cverack))

	// wait for version message and send verack
	m = msg.Must(msg.ReadKind(conn, msg.Cversion))
	resp.Ver, err = payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}
	defer func() { n.VerIn <- resp }()

	if _, err := conn.Write(msg.New(msg.Cverack, []byte{}).Encode()); err != nil {
		panic(err)
	}

	// send addr and inv messages
	am := msg.New(msg.Caddr, payload.AddrEncode(req.Peers...))
	if _, err := conn.Write(am.Encode()); err != nil {
		panic(err)
	}

	im := msg.New(msg.Cinv, payload.InventoryEncode(req.Inv))
	if _, err := conn.Write(im.Encode()); err != nil {
		panic(err)
	}

	// wait for addr and inv messages
	m = msg.Must(msg.ReadKind(conn, msg.Caddr))
	resp.Peers, err = payload.AddrDecode(m.Payload())
	if err != nil {
		panic(err)
	}

	m = msg.Must(msg.ReadKind(conn, msg.Cinv))
	resp.Inv, err = payload.InventoryDecode(m.Payload())
	if err != nil {
		panic(err)
	}
}

func (n *Node) VersionExchange(addr *payload.AddressInfo) {
	vcopy := *n.MyVer
	vcopy.Timestamp = time.Now()
	vcopy.ToAddr = addr
	n.verOut <- &VerDat{&vcopy, n.MyPeers, n.MyInv}
}

func (n *Node) Broadcast(m *msg.Msg) {
	n.objectsOut <- m
}

func (n *Node) broadcastObj() {
	m := <-n.objectsOut
	_ = m

	panic("not implemented")
}

func (n *Node) respondGetData(m *msg.Msg, conn net.Conn) {
	panic("not implemented")
}

func (nd *Node) GetData(addr string, hashes [][]byte) (n int, err error) {
	conn, err := dial(addr)
	if err != nil {
		return n, err
	}
	defer conn.Close()

	m := msg.New(msg.Cgetdata, payload.GetDataEncode(hashes))
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
