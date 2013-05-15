package p2p

import (
	"fmt"
	"io"
	"net"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
)

const (
	DefaultTimeout = 30 * time.Second
)

type Handler interface {
	Handle(conn net.Conn)
}

// Send opens a stream with the peer at addr and sends encoded message m.
// Received responses and further back/forth communication will be passed
// to the handler.  h is responsible for closing the connection when
// finished.  Send blocks until h or the peer closes the connection.
func Send(addr string, m *msg.Msg, h Handler) error {
	conn, err := net.DialTimeout("tcp", addr, DefaultTimeout)
	if err != nil {
		return err
	}

	if _, err := conn.Write(m.Encode()); err != nil {
		return err
	}

	for {
		if _, err := conn.Read(make([]byte, 0)); err != nil && err != io.EOF {
			// gracefully handle connections closed by handler
			return nil
		}
		h.Handle(conn)
	}
	return nil
}

type Node struct {
	Addr string
	handler   Handler
}


// NewNode creates and returns a new p2p node that listens on network
// address addr.  Incoming message streams from other nodes are passed to
// h.  h is responsible for closing connections when finished.
func NewNode(addr string, h Handler) *Node {
	return &Node{
		Addr: addr,
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
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()
	for {
		if _, err := conn.Read(make([]byte, 0)); err != nil && err != io.EOF {
			// gracefully handle connections closed by handler
			return
		}
		n.handler.Handle(conn)
	}
}

