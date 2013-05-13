package p2p

import (
	"io"
	"net"

	"github.com/rwcarlsen/gobitmsg/msg"
)

type Handler interface {
	Handle(w io.Writer, m *msg.Msg)
}

// Send sends message m to another p2p node at addr.  If message m fails
// to be sent, an error is returned.  If the receiver does not respond or
// responds with an invalid message, an error is returned.
func Send(addr string, m *msg.Msg) (resp *msg.Msg, err error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	_, err = conn.Write(m.Encode())
	if err != nil {
		return nil, err
	}

	resp, err = msg.Decode(conn)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

type Node struct {
	addr    string
	handler Handler
}

// NewNode creates and returns a new p2p node that listens on network
// address addr.  Incoming messages from other nodes are passed to h.
func NewNode(addr string, h Handler) *Node {
	return &Node{
		addr:    addr,
		handler: h,
	}
}

// Addr returns the local network address this node listens on.
func (n *Node) Addr() string {
	return n.addr
}

func (n *Node) GetHandler() Handler {
	return n.handler
}

// ListenAndServe sets the node to begin listening for and serving messages
// to/from other nodes in daemon mode.  This method does not block and
// returns immediately.
func (n *Node) ListenAndServe() error {
	if err := n.listen(); err != nil {
		return err
	}
	return nil
}

func (n *Node) listen() error {
	ln, err := net.Listen("tcp", n.addr)
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
	m, err := msg.Decode(conn)
	if err != nil {
		// log error
		return
	}
	n.handler.Handle(conn, m)
	conn.Close()
}

