package payload

import (
	"encoding/binary"
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

// Message encodings
const (
	EncIgnore = iota
	EncTrivial
	EncSimple
)

type MsgInfo struct {
	MsgVersion  int // VarInt
	AddrVersion int // VarInt
	Stream      int // VarInt
	Behavior    uint32
	SignKey     *Key
	EncryptKey  *Key
	DestRipe    []byte
	Encoding    int // VarInt
	Content     []byte
	AckData     []byte
	signature   []byte
}

// Encode encodes MsgInfo struct into a byte slice.
func (m *MsgInfo) Encode() []byte {
	data := varIntEncode(m.MsgVersion)
	data = append(data, varIntEncode(m.AddrVersion)...)
	data = append(data, varIntEncode(m.Stream)...)
	data = append(data, packUint(order, m.Behavior)...)
	data = append(data, m.SignKey.EncodePub()...)
	data = append(data, m.EncryptKey.EncodePub()...)
	data = append(data, m.DestRipe...)
	data = append(data, varIntEncode(m.Encoding)...)
	data = append(data, varIntEncode(len(m.Content))...)
	data = append(data, m.Content...)
	data = append(data, varIntEncode(len(m.AckData))...)
	data = append(data, m.AckData...)

	var err error
	if m.signature, err = m.SignKey.Sign(data); err != nil {
		panic("signature failed")
	}
	data = append(data, varIntEncode(len(m.signature))...)
	data = append(data, m.signature...)

	return data
}

func (m *MsgInfo) Signature() []byte {
	return m.signature
}

func MsgInfoDecode(data []byte) *MsgInfo {
	m := &MsgInfo{}
	var offset, n, length int

	m.MsgVersion, offset = varIntDecode(data)

	m.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	m.Stream, n = varIntDecode(data[offset:])
	offset += n

	m.Behavior = order.Uint32(data[offset : offset+4])
	offset += 4

	m.SignKey, n = DecodePubKey(data[offset:])
	offset += n

	m.EncryptKey, n = DecodePubKey(data[offset:])
	offset += n

	m.DestRipe = append([]byte{}, data[offset:offset+20]...)
	offset += 20

	m.Encoding, n = varIntDecode(data[offset:])
	offset += n

	length, n = varIntDecode(data[offset:])
	offset += n

	m.Content = append([]byte{}, data[offset:offset+length]...)
	offset += length

	length, n = varIntDecode(data[offset:])
	offset += n

	m.AckData = append([]byte{}, data[offset:offset+length]...)
	offset += length

	length, n = varIntDecode(data[offset:])
	offset += n

	m.signature = append([]byte{}, data[offset:offset+length]...)

	return m
}

type BroadcastInfo struct {
	BroadcastVersion int
	AddrVersion      int
	Stream           int
	Behavior         uint32
	SignKey          *Key
	EncryptKey       *Key
	TrialsPerByte    int
	ExtraBytes       int
	Encoding         int
	Msg              []byte
	signature        []byte
}

func BroadcastInfoDecode(data []byte) *BroadcastInfo {
	b := &BroadcastInfo{}
	var length, offset, n int

	b.BroadcastVersion, n = varIntDecode(data[offset:])
	offset += n

	b.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	b.Stream, n = varIntDecode(data[offset:])
	offset += n

	b.Behavior = order.Uint32(data[offset : offset+4])
	offset += 4

	b.SignKey, n = DecodePubKey(data[offset:])
	offset += n

	b.EncryptKey, n = DecodePubKey(data[offset:])
	offset += n

	b.TrialsPerByte, n = varIntDecode(data[offset:])
	offset += n

	b.ExtraBytes, n = varIntDecode(data[offset:])
	offset += n

	b.Encoding, n = varIntDecode(data[offset:])
	offset += n

	length, n = varIntDecode(data[offset:])
	offset += n

	b.Msg = append([]byte{}, data[offset:offset+length]...)
	offset += length

	length, n = varIntDecode(data[offset:])
	offset += n

	b.signature = append([]byte{}, data[offset:offset+length]...)

	return b
}

func (b *BroadcastInfo) Encode() []byte {
	data := varIntEncode(b.BroadcastVersion)
	data = append(data, varIntEncode(b.AddrVersion)...)
	data = append(data, varIntEncode(b.Stream)...)
	data = append(data, packUint(order, b.Behavior)...)
	data = append(data, b.SignKey.EncodePub()...)
	data = append(data, b.EncryptKey.EncodePub()...)
	data = append(data, varIntEncode(b.TrialsPerByte)...)
	data = append(data, varIntEncode(b.ExtraBytes)...)
	data = append(data, varIntEncode(b.Encoding)...)
	data = append(data, varIntEncode(len(b.Msg))...)
	data = append(data, b.Msg...)

	var err error
	if b.signature, err = b.SignKey.Sign(data); err != nil {
		panic("signature failed")
	}
	data = append(data, varIntEncode(len(b.signature))...)
	data = append(data, b.signature...)

	return data
}

func (b *BroadcastInfo) Signature() []byte {
	return b.signature
}
