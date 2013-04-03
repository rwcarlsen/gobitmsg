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
	Nonce     uint
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
	order.PutUint64(tmp, uint64(v.Nonce))
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

	v.Nonce = uint(order.Uint64(data[offset : offset+8]))
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
