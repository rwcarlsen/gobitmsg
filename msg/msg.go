package msg

import (
	"crypto"
	_ "crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	Magic = 0xE9BEB4D9
	Hash  = crypto.SHA512
)

type Command string

// message types
const (
	Cversion   Command = "version"
	Cverack            = "verack"
	Caddr              = "addr"
	Cinv               = "inv"
	Cgetdata           = "getdata"
	CgetpubKey         = "getpubkey"
	Cpubkey            = "pubkey"
	Cmsg               = "msg"
	Cbroadcast         = "broadcast"
)

var Order = binary.BigEndian

func ReadKind(r io.Reader, cmd Command) (*Msg, error) {
	m, err := Decode(r)
	if err != nil {
		return nil, err
	} else if m.Cmd() != cmd {
		return nil, fmt.Errorf("msg: decoded msg of wrong type (expected %v, got %v)", cmd, m.Cmd())
	}
	return m, nil
}

func Must(m *Msg, err error) *Msg {
	if err != nil {
		panic(err)
	}
	return m
}

type Msg struct {
	magic   uint32
	command Command
	payload []byte
	// length of the payload
	length uint32
	// first 4 bytes of payload's sha512
	checksum uint32
}

func New(cmd Command, payload []byte) *Msg {
	h := Hash.New()
	_, err := h.Write(payload)
	if err != nil {
		panic(err)
	}
	slice := h.Sum(nil)
	sum := Order.Uint32(slice[:4])

	return &Msg{
		magic:    Magic,
		command:  cmd,
		payload:  payload,
		length:   uint32(len(payload)),
		checksum: sum,
	}
}

func Decode(r io.Reader) (*Msg, error) {
	buf := make([]byte, 24)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	magic := Order.Uint32(buf[:4])
	command := Command(nullUnpad(buf[4:16]))
	length := Order.Uint32(buf[16:20])
	checksum := Order.Uint32(buf[20:24])

	data := make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}

	m := &Msg{
		magic:    magic,
		command:  command,
		length:   length,
		checksum: checksum,
		payload:  data,
	}

	if !m.validChecksum() {
		return nil, fmt.Errorf("msg: message decode failed - bad checksum")
	} else if m.magic != Magic {
		return nil, fmt.Errorf("msg: message decode failed - invalid magic '%x'", m.magic)
	}

	return m, nil
}

func (m *Msg) Encode() []byte {
	data := make([]byte, 24, 24+m.length)
	cmd := nullPad([]byte(m.command), 12)

	Order.PutUint32(data[:4], m.magic)
	copy(data[4:16], cmd)
	Order.PutUint32(data[16:20], m.length)
	Order.PutUint32(data[20:24], m.checksum)
	return append(data, m.payload...)
}

func (m *Msg) Cmd() Command {
	return m.command
}

func (m *Msg) Payload() []byte {
	return m.payload
}

func (m *Msg) validChecksum() bool {
	h := Hash.New()
	_, err := h.Write(m.Payload())
	if err != nil {
		panic(err)
	}
	return Order.Uint32(h.Sum(nil)[:4]) == m.checksum
}

func nullPad(data []byte, totLen int) []byte {
	padded := append([]byte{}, data...)
	for len(padded) < totLen {
		padded = append(padded, 0x00)
	}
	return padded
}

func nullUnpad(data []byte) []byte {
	for i, b := range data {
		if b == 0x00 {
			return data[:i]
		}
	}
	return data
}
