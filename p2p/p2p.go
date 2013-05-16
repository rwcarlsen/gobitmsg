package p2p

import (
	"fmt"
	"io"
	"net"
	"time"
)

const (
	DefaultTimeout = 7 * time.Second
)

// Dial opens a stream with the peer at addr.
func Dial(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", addr, DefaultTimeout)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

type Handler interface {
	Handle(conn net.Conn)
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
