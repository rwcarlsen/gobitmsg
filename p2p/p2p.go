package p2p

import (
	"fmt"
	"log"
	"net"
	"time"
	"os"

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
		Addr: addr.Addr(),
		Log: log.New(os.Stdout, name + ": ", log.LstdFlags),
		Objects: make(chan *msg.Msg),
		Ver: make(chan *VerResp),
		MyVer: ver,
		MyAddrList: []*payload.AddressInfo{},
		MyInvList: [][]byte{},
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

type VerResp struct {
	OtherVer   *payload.Version
	OtherPeers []*payload.AddressInfo
	OtherInv   [][]byte
}

type Node struct {
	Addr       string
	Log        *log.Logger
	Objects    chan *msg.Msg
	Ver        chan *VerResp
	MyVer      *payload.Version
	MyAddrList []*payload.AddressInfo
	MyInvList  [][]byte
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
		n.Objects <- m
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
	vr := &VerResp{}

	vr.OtherVer, err = payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}

	defer func() { n.Ver <- vr }()

	if _, err := conn.Write(msg.New(msg.Cverack, []byte{}).Encode()); err != nil {
		panic(err)
	}

	// send version msg and wait for verack
	vcopy := *n.MyVer
	vcopy.Timestamp = time.Now()
	vcopy.ToAddr = vr.OtherVer.FromAddr
	m = msg.New(msg.Cversion, vcopy.Encode())
	if _, err := conn.Write(m.Encode()); err != nil {
		panic(err)
	}

	msg.Must(msg.ReadKind(conn, msg.Cverack))

	// send addr and inv messages
	am := msg.New(msg.Caddr, payload.AddrEncode(n.MyAddrList...))
	if _, err := conn.Write(am.Encode()); err != nil {
		panic(err)
	}

	im := msg.New(msg.Cinv, payload.InventoryEncode(n.MyInvList))
	if _, err := conn.Write(im.Encode()); err != nil {
		panic(err)
	}

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
}

// VersionExchanges initiates and performs a version exchange sequence with
// the node at addr.
func (n *Node) VersionExchange(addr *payload.AddressInfo) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("version exchange failed (%v)", r)
		}
	}()

	n.Log.Printf("Dialing address %v", addr.Addr())
	conn, err := dial(addr.Addr())
	if err != nil {
		return err
	}
	defer conn.Close()

	vr := &VerResp{}

	// send version msg and wait for verack
	vcopy := *n.MyVer
	vcopy.Timestamp = time.Now()
	vcopy.ToAddr = addr
	m := msg.New(msg.Cversion, vcopy.Encode())
	if _, err := conn.Write(m.Encode()); err != nil {
		panic(err)
	}

	msg.Must(msg.ReadKind(conn, msg.Cverack))

	// wait for version message and send verack
	m = msg.Must(msg.ReadKind(conn, msg.Cversion))
	vr.OtherVer, err = payload.VersionDecode(m.Payload())
	if err != nil {
		panic(err)
	}
	defer func() { n.Ver <- vr }()

	if _, err := conn.Write(msg.New(msg.Cverack, []byte{}).Encode()); err != nil {
		panic(err)
	}

	// send addr and inv messages
	am := msg.New(msg.Caddr, payload.AddrEncode(n.MyAddrList...))
	if _, err := conn.Write(am.Encode()); err != nil {
		panic(err)
	}

	im := msg.New(msg.Cinv, payload.InventoryEncode(n.MyInvList))
	if _, err := conn.Write(im.Encode()); err != nil {
		panic(err)
	}

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

	return nil
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
		nd.Objects <- m
		n++
	}
	return n, nil
}
