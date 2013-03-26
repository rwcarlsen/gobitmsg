
package message

import (
	"crypto"
	_ "crypto/sha512"
	"encoding/binary"
)

const (
	Magic = 0xE9BEB4D9
	Hash = crypto.SHA512
)

var order = binary.BigEndian

type Message interface {
	Command() string
	Payload() []byte
	Len() uint32
	Checksum() uint32
	Magic() uint32
}

type msg struct {
	magic uint32
	command string
	payload []byte
	// length of the payload
	length uint32
	// first 4 bytes of payload's sha512
	checksum uint32
}

func New(cmd string, payload []byte) Message {
	h := Hash.New()
	_, err := h.Write(payload)
	if err != nil {
		panic(err)
	}
	slice := h.Sum(nil)
	sum := order.Uint32(slice[:4])

	return &msg{
		magic: Magic,
		command: cmd,
		payload: payload,
		length: uint32(len(payload)),
		checksum: sum,
	}
}

func (m *msg) Magic() uint32 {
	return m.magic
}

func (m *msg) Command() string {
	return m.command
}

func (m *msg) Payload() []byte {
	return m.payload
}

func (m *msg) Len() uint32 {
	return m.length
}

func (m *msg) Checksum() uint32 {
	return m.checksum
}

func Encode(m Message) []byte {
	data := make([]byte, 24, 24 + m.Len())
	cmd := nullPad([]byte(m.Command()), 12)

	order.PutUint32(data[:4], m.Magic())
	copy(data[4:16], cmd)
	order.PutUint32(data[16:20], m.Len())
	order.PutUint32(data[20:24], m.Checksum())
	return append(data, m.Payload()...)
}

func Decode(data []byte) Message {
	return &msg{
		magic: order.Uint32(data[:4]),
		command: string(nullUnpad(data[4:16])),
		length: order.Uint32(data[16:20]),
		checksum: order.Uint32(data[20:24]),
		payload: data[24:],
	}
}

func nullPad(data []byte, totLen int) []byte {
	padded = append([]byte{}, data...)
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

func IsValid(m Message) bool {
	validLen := m.Len() == len(m.Payload())
	validSum := isChecksumValid(m)
	validMagic := m.Magic() == Magic

	return validLen && validSum && validMagic
}

func isChecksumValid(m Message) bool {
	h := Hash.New()
	_, err := h.Write(m.Payload())
	if err != nil {
		panic(err)
	}

	return order.Uint32(h.Sum(nil)[:4]) == m.Checksum()
}

