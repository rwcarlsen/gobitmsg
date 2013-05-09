package p2p

import (
	"io"
	"net"

	"github.com/rwcarlsen/gobitmsg/msg"
)

type Handler interface {
	Handle(w io.Writer, m *msg.Msg)
}

type Node struct {
	addr    string
	done    chan bool
	handler Handler
}

// NewNode creates and returns a new p2p node that listens on network
// address addr.  Incoming messages from other nodes are passed to h.
func NewNode(addr string, h Handler) *Node {
	return &Node{
		addr:    addr,
		handler: h,
		done:    make(chan bool),
	}
}

// Addr returns the local network address this node listens on.
func (n *Node) Addr() string {
	return n.addr
}

// Send sends message m to another p2p node at addr.  If message m fails
// to be sent, an error is returned.  If the receiver does not respond or
// responds with an invalid message, an error is returned.
func (n *Node) Send(addr string, m *msg.Msg) (resp *msg.Msg, err error) {
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

// Start sets the node to begin listening for and serving messages to/from
// other nodes in daemon mode.  This method does not block and returns
// immediately.
func (n *Node) Start() error {
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
			select {
			case <-n.done:
				return
			default:
				conn, err := ln.Accept()
				if err != nil {
					continue
				}
				go n.handleConn(conn)
			}
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

// Stop stops a started node from network listening/serving. Do not call
// Stop without first calling Start successfully (no error returned).
func (n *Node) Stop() {
	n.done <- true
}

