package payload

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Message encodings
const (
	EncIgnore = iota
	EncTrivial
	EncSimple
)

func packUint(order binary.ByteOrder, v interface{}) (data []byte) {
	switch val := v.(type) {
	case uint64:
		data = make([]byte, 8)
		order.PutUint64(data, val)
	case uint32:
		data = make([]byte, 4)
		order.PutUint32(data, val)
	case uint16:
		data = make([]byte, 2)
		order.PutUint16(data, val)
	case uint8:
		data = []byte{byte(val)}
	default:
		panic("unsupported type")
	}
	return data
}

// varIntEncode encodes an int as a variable length int.  i must
// be positive.
func varIntEncode(i int) (data []byte) {
	v := uint64(i)
	switch {
	case v < 0xFD:
		return []byte{byte(v)}
	case v <= 0xFFFF:
		data = make([]byte, 3)
		data[0] = 0xFD
		order.PutUint16(data[1:], uint16(v))
		return data
	case v <= 0xFFFFFFFF:
		data = make([]byte, 5)
		data[0] = 0xFE
		order.PutUint32(data[1:], uint32(v))
		return data
	default:
		data = make([]byte, 9)
		data[0] = 0xFF
		order.PutUint64(data[1:], uint64(v))
		return data
	}
	panic("not reached")
}

// varIntDecode decodes a variable length integer from data and returns the
// value along with the total number of bytes decoded from data.  Bytes
// after the decoded value are ignored.
func varIntDecode(data []byte) (val int, n int) {
	switch data[0] {
	case 0xFF:
		return int(order.Uint64(data[1:9])), 9
	case 0xFE:
		return int(order.Uint32(data[1:5])), 5
	case 0xFD:
		return int(order.Uint16(data[1:3])), 3
	default:
		return int(data[0]), 1
	}
	panic("not reached")
}

// varStrEncode encodes a string as a variable length string.
func varStrEncode(s string) []byte {
	return append(varIntEncode(len(s)), []byte(s)...)
}

// varStrDecode decodes a variable length string from data and returns the
// string along with the total number of bytes decoded from data.  Bytes
// after a decoded VarString are ignored.
func varStrDecode(data []byte) (s string, n int) {
	length, n := varIntDecode(data)
	return string(data[n : n+length]), n + length
}

// intListEncode encodes a slice of integers as a variable length
// IntList. All integers must be positive.
func intListEncode(vals []int) []byte {
	data := varIntEncode(len(vals))
	for _, v := range vals {
		data = append(data, varIntEncode(v)...)
	}
	return data
}

// intListDecode decodes a variable length IntList from data and returns the
// an int slice along with the total number of bytes decoded from data.  Bytes
// after the decoded list are ignored.
func intListDecode(data []byte) (v []int, n int) {
	length, offset := varIntDecode(data)
	vals := make([]int, length)
	for i := 0; i < length; i++ {
		val, n := varIntDecode(data[offset:])
		offset += n
		vals[i] = val
	}
	return vals, offset
}

type AddressInfo struct {
	Time     time.Time
	Stream   int
	Services uint64
	Ip       string
	Port     int
}

// addressInfoDecode decodes an address info structure from data and
// returns the it along with the total number of bytes decoded from data.
// Bytes after the decoded struct are ignored.
func addressInfoDecode(data []byte) (v *AddressInfo, n int) {
	return &AddressInfo{
		Time:     time.Unix(int64(order.Uint32(data[:4])), 0),
		Stream:   int(order.Uint32(data[4:8])),
		Services: order.Uint64(data[8:16]),
		Ip:       unpackIp(data[16:32]),
		Port:     int(order.Uint16(data[32:34])),
	}, 34
}

// addressInfoDecodeShort decodes an address info structure from data and
// returns the it along with the total number of bytes decoded from data.
// Bytes after the decoded struct are ignored.
func addressInfoDecodeShort(data []byte) (v *AddressInfo, n int) {
	return &AddressInfo{
		Services: order.Uint64(data[:8]),
		Ip:       unpackIp(data[8:24]),
		Port:     int(order.Uint16(data[24:26])),
	}, 26
}

func (ai *AddressInfo) encode() []byte {
	data := make([]byte, 34)

	order.PutUint32(data[:4], uint32(ai.Time.Unix()))
	order.PutUint32(data[4:8], uint32(ai.Stream))
	order.PutUint64(data[8:16], ai.Services)
	packIp(data[16:32], ai.Ip)
	order.PutUint16(data[32:34], uint16(ai.Port))

	return data
}

func (ai *AddressInfo) encodeShort() []byte {
	return ai.encode()[8:]
}

func packIp(data []byte, ip string) {
	points := strings.Split(ip, ".")
	if l := len(points); l != 4 {
		panic("Invalid/unsupported Ip: " + ip)
	}

	for i := range data[:12] {
		data[i] = 0
	}

	data[10] = 0xFF
	data[11] = 0xFF

	for i, p := range points {
		v, err := strconv.Atoi(p)
		if err != nil {
			panic("Invalid Ip: " + ip)
		}
		data[i+12] = byte(v)
	}
}

func unpackIp(data []byte) string {
	if data[10] != 0xFF || data[11] != 0xFF {
		panic(fmt.Sprintf("Invalid/unsupported Ip: %x", data[:16]))
	}
	return fmt.Sprintf("%d.%d.%d.%d", data[12], data[13], data[14], data[15])
}

type MsgInfo struct {
	MsgVersion  int // VarInt
	AddrVersion int // VarInt
	Stream      int // VarInt
	Behavior    uint32
	SignKey     []byte
	EncryptKey  []byte
	DestRipe    []byte
	Encoding    int // VarInt
	MsgLen      int // VarInt
	Content     []byte
	AckLen      int // VarInt
	AckData     []byte
	SigLen      int // VarInt
	Signature   []byte
}

// msgInfoEncode decodes and returns a MsgInfo struct from data along with the
// total number of bytes decoded from data.  Bytes after the decoded MsgInfo
// struct are ignored.
func msgInfoEncode(m *MsgInfo) []byte {
	data := varIntEncode(m.MsgVersion)
	data = append(data, varIntEncode(m.AddrVersion)...)
	data = append(data, varIntEncode(m.Stream)...)
	data = append(data, packUint(order, m.Behavior)...)
	data = append(data, m.SignKey...)
	data = append(data, m.EncryptKey...)
	data = append(data, m.DestRipe...)
	data = append(data, varIntEncode(m.Encoding)...)
	data = append(data, varIntEncode(m.MsgLen)...)
	data = append(data, m.Content...)
	data = append(data, varIntEncode(m.AckLen)...)
	data = append(data, m.AckData...)
	data = append(data, varIntEncode(m.SigLen)...)
	data = append(data, m.Signature...)

	return data
}

func msgInfoDecode(data []byte) *MsgInfo {
	m := &MsgInfo{}
	var offset, n int

	m.MsgVersion, offset = varIntDecode(data)

	m.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	m.Stream, n = varIntDecode(data[offset:])
	offset += n

	m.Behavior = order.Uint32(data[offset : offset+4])
	offset += 4

	m.SignKey = append([]byte{}, data[offset:offset+64]...)
	offset += 64

	m.EncryptKey = append([]byte{}, data[offset:offset+64]...)
	offset += 64

	m.EncryptKey = append([]byte{}, data[offset:offset+20]...)
	offset += 20

	m.Encoding, n = varIntDecode(data[offset:])
	offset += n

	m.MsgLen, n = varIntDecode(data[offset:])
	offset += n

	m.Content = append([]byte{}, data[offset:offset+m.MsgLen]...)
	offset += m.MsgLen

	m.AckLen, n = varIntDecode(data[offset:])
	offset += n

	m.AckData = append([]byte{}, data[offset:offset+m.AckLen]...)
	offset += m.AckLen

	m.SigLen, n = varIntDecode(data[offset:])
	offset += n

	m.Signature = append([]byte{}, data[offset:offset+m.SigLen]...)

	return m
}
