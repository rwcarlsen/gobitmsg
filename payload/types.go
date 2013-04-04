package payload

import (
	"fmt"
	"strconv"
)

// Message encodings
const (
	EncIgnore = iota
	EncTrivial
	EncSimple
)

// varIntEncode encodes an int as a variable length int.  v must
// be positive.
func varIntEncode(v int) []byte {
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
	data := varIntEncode(len(v))
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

func addressInfoEncode(v *AddressInfo) []byte {
	data := make([]byte, 34)

	order.PutUint32(data[:4], uint32(v.Time.Unix()))
	order.PutUint32(data[4:8], uint32(v.Stream))
	order.PutUint64(data[8:16], v.Services)
	packIp(data[16:32], v.Ip)
	order.PutUint16(data[32:34], uint16(v.Port))

	return data
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
	}
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
	return fmt.Sprintf("%v.%v.%v.%v", data[12:16]...)
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

	tmp := make([]byte, 4)
	order.PutUint32(tmp, m.Behavior)
	data = append(data, tmp...)

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

	v, offset := varIntDecode(data)
	m.MsgVersion = v

	v, n := varIntDecode(data[offset:])
	m.AddrVersion = v
	offset += n

	v, n = varIntDecode(data[offset:])
	m.Stream = v
	offset += n

	v = order.Uint32(data[offset : offset+4])
	m.Stream = v
	offset += 4

	tmp := make([]byte, 0, 64)
	tmp = append(tmp, data[offset:offset+64]...)
	m.SignKey = tmp
	offset += 64

	tmp = make([]byte, 0, 64)
	tmp = append(tmp, data[offset:offset+64]...)
	m.EncryptKey = tmp
	offset += 64

	tmp = make([]byte, 0, 20)
	tmp = append(tmp, data[offset:offset+20]...)
	m.EncryptKey = tmp
	offset += 20

	v, n = varIntDecode(data[offset:])
	m.Encoding = v
	offset += n

	v, n = varIntDecode(data[offset:])
	m.MsgLen = v
	offset += n

	tmp = make([]byte, 0, m.MsgLen)
	tmp = append(tmp, data[offset:offset+m.MsgLen]...)
	m.Content = tmp
	offset += m.MsgLen

	v, n = varIntDecode(data[offset:])
	m.AckLen = v
	offset += n

	tmp = make([]byte, 0, m.AckLen)
	tmp = append(tmp, data[offset:offset+m.AckLen]...)
	m.AckData = tmp
	offset += m.AckLen

	v, n = varIntDecode(data[offset:])
	m.SigLen = v
	offset += n

	tmp = make([]byte, 0, m.SigLen)
	tmp = append(tmp, data[offset:offset+m.SigLen]...)
	m.Signature = tmp

	return m
}
