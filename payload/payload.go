package payload

import (
	"crypto/sha512"
	"time"

	"github.com/rwcarlsen/gobitmsg/message"
)

var order = message.Order

type Version struct {
	Ver       int
	Services  uint64
	Timestamp time.Time
	ToAddr    *AddressInfo
	FromAddr  *AddressInfo
	Nonce     uint64
	UserAgent string // var_str
	Streams   []int  // var_int_list
}

func EncodeVersion(v *Version) []byte {
	tmp := make([]byte, 4)
	order.PutUint32(tmp, uint32(v.Services))
	data := append(data, tmp...)

	tmp = make([]byte, 8)
	order.PutUint64(tmp, v.Services)
	data = append(data, tmp...)

	tmp = make([]byte, 8)
	order.PutUint64(tmp, v.Timestamp.Unix())
	data = append(data, tmp...)

	data = append(data, addressInfoEncode(v.ToAddr)...)
	data = append(data, addressInfoEncode(v.FromAddr)...)

	tmp = make([]byte, 8)
	order.PutUint64(tmp, v.Nonce)
	data = append(data, tmp...)

	data = append(data, varStrEncode(v.UserAgent)...)
	data = append(data, intListEncode(v.Streams)...)

	return data
}

func DecodeVersion(data []byte) *Version {
	v := &Version{}

	v.Ver = int(order.Uint32(data[:4]))
	offset := 4

	v.Services = order.Uint64(data[offset : offset+8])
	offset += 8

	sec = order.Uint64(data[offset : offset+8])
	v.Timestamp = time.Unix(sec, 0)
	offset += 8

	v.ToAddr, n = addressInfoDecode(data[offset:])
	offset += n

	v.FromAddr, n = addressInfoDecode(data[offset:])
	offset += n

	v.Nonce = order.Uint64(data[offset : offset+8])
	offset += 8

	v.UserAgent, n = varStrDecode(data[offset:])
	offset += n

	v.Streams, _ = intListDecode(data[offset:])

	return v
}

func EncodeAddr(addresses []*AddressInfo) []byte {
	data := varIntEncode(len(addresses))

	for _, addr := range addresses {
		data = append(data, addressInfoEncode(addr)...)
	}
}

func DecodeAddr(data []byte) []*AddressInfo {
	nAddr, offset := varIntDecode(data)
	addresses = make([]*AddressInfo, nAddr)
	for i := 0; i < nAddr; i++ {
		addr, n := addressInfoDecode(data[offset:])
		addresses[i] = addr
		offset += n
	}
	return addresses
}

func EncodeInventory(objData [][]byte) []byte {
	h := sha512.New()
	data := varIntEncode(len(objData))

	for _, data := range objData {
		h.Reset()
		h.Write(data)
		sum := h.Sum(nil)
		h.Reset()
		h.Write(sum)
		sum = h.Sum(nil)
		data = append(data, sum[:32]...)
	}

	return data
}

func DecodeInventory(data []byte) [][]byte {
	nObj, offset := varIntDecode(data)
	objData = make([][]byte, nObj)
	for i := 0; i < nObj; i++ {
		start := offset + i*32
		end := start + 32
		objData = append(objData, data[start:end])
	}
	return objData
}

func EncodeGetData(hashes [][]byte) []byte {
	data := varIntEncode(len(hashes))
	for _, sum := range hashes {
		data = append(data, sum...)
	}
	return data
}

func DecodeGetData(data []byte) [][]byte {
	nHashes, offset := varIntDecode(data)
	hashes = make([][]byte, nHashes)
	for i := 0; i < nHashes; i++ {
		start := offset + i*32
		end := start + 32
		hashes = append(hashes, data[start:end])
	}
	return hashes
}

type GetPubKey struct {
	PowNonce    uint64
	Time        time.Time // uint32
	AddrVersion int       // var_int
	Stream      int       // var_int
	RipeHash    []byte    // len=20
}

func EncodeGetPubkey(g *GetPubKey) []byte {
	data := make([]byte, 8)
	order.PutUint64(data, g.PowNonce)

	tmp := make([]byte, 4)
	order.PutUint32(tmp, uint32(g.Time.Unix()))
	data = append(data, tmp...)

	data = append(data, varIntEncode(g.AddrVersion)...)
	data = append(data, varIntEncode(g.Stream)...)
	data = append(data, g.Hash...)

	return data
}

func DecodeGetPubKey(data []byte) *GetPubKey {
	g := &GetPubKey{}

	g.PowNonce = order.Uint64(data[:8])
	offset := 8

	g.Time = time.Unix(order.Uint64(data[offset:offset+4]), 0)
	offset += 4

	var n int
	g.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	g.Stream, n = varIntDecode(data[offset:])
	offset += n

	g.RipeHash = data[offset:]

	return g
}

type PubKey struct {
	PowNonce    uint64
	Time        time.Time // uint32
	AddrVersion int       // var_int
	Stream      int       // var_int
	Behavior    uint32    // bitfield
	SignKey     []byte    // len=64
	EncryptKey  []byte    // len=64
}
