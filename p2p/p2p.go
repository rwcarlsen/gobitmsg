package p2p

import (
	"io"
	"net"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
)

const (
	DefaultTimeout = 10 * time.Second
)

type Handler interface {
	Handle(w io.WriteCloser, m *msg.Msg)
}

type Peer struct {
	Addr string
}

func NewPeer(addr string) *Peer {
	return &Peer{
		Addr: addr,
	}
}

// Send opens a stream with the peer and sends encoded message m.
// Received responses and further back/forth communication will be passed
// to the handler.  h is responsible for closing the connection when
// finished.  Send blocks until h closes the connection.
func (p *Peer) Send(m *msg.Msg, h Handler) error {
	conn, err := net.DialTimeout("tcp", p.Addr, DefaultTimeout)
	if err != nil {
		return err
	}

	if _, err := conn.Write(m.Encode()); err != nil {
		return err
	}

	for {
		// gracefully handle connections closed by handler
		if _, err := conn.Read(make([]byte, 0)); err != nil && err != io.EOF {
			return nil
		}

		m, err := msg.Decode(conn)
		if err != nil {
			return err
		}
		h.Handle(conn, m)
	}
}

type Node struct {
	Addr    string
	handler Handler
}

// NewNode creates and returns a new p2p node that listens on network
// address addr.  Incoming message streams from other nodes are passed to
// h.  h is responsible for closing connections when finished.
func NewNode(addr string, h Handler) *Node {
	return &Node{
		Addr:    addr,
		handler: h,
	}
}

// Start sets the node to begin listening for and serving messages
// to/from other nodes in daemon mode.  This method does not block and
// returns immediately.
func (n *Node) Start() error {
	if err := n.listen(); err != nil {
		return err
	}
	return nil
}

func (n *Node) listen() error {
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
	for {
		m, err := msg.Decode(conn)
		if err != nil {
			// log error
			return
		}
		n.handler.Handle(conn, m)
	}
}
