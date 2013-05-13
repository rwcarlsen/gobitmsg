package msg

import (
	"io"
	"crypto"
	_ "crypto/sha512"
	"encoding/binary"
)

const (
	Magic           = 0xE9BEB4D9
	Hash            = crypto.SHA512
	ProtocolVersion = 1
)

type Command string

// message types
const (
	Cversion    Command = "version"
	CversionAck         = "verack"
	Caddress            = "addr"
	Cinventory          = "inv"
	CgetData            = "getdata"
	CgetPubKey          = "getpubkey"
	CpubKey             = "pubkey"
	Cmsg                = "msg"
	Cbroadcast          = "broadcast"
)

var Order = binary.BigEndian

type Encoder interface {
	Encode() []byte
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

	return &Msg{
		magic: magic,
		command: command,
		length: length,
		checksum: checksum,
		payload:  data,
	}, nil
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

func (m *Msg) Magic() uint32 {
	return m.magic
}

func (m *Msg) Cmd() Command {
	return m.command
}

func (m *Msg) Payload() []byte {
	return m.payload
}

func (m *Msg) Len() uint32 {
	return m.length
}

func (m *Msg) Checksum() uint32 {
	return m.checksum
}

func (m *Msg) IsValid() bool {
	validLen := int(m.Len()) == len(m.Payload())
	validSum := m.isChecksumValid()
	validMagic := m.Magic() == Magic

	return validLen && validSum && validMagic
}

func (m *Msg) isChecksumValid() bool {
	h := Hash.New()
	_, err := h.Write(m.Payload())
	if err != nil {
		panic(err)
	}

	return Order.Uint32(h.Sum(nil)[:4]) == m.Checksum()
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

