package payload

import (
	"fmt"
	"time"
)

func p2_VersionDecode(data []byte) (v *Version, err error) {
	defer func() {
		if r := recover(); r != nil {
			v = nil
			err = fmt.Errorf("payload: failed to decode version payload (malformed)")
		}
	}()

	v = &Version{}
	var n int

	v.protocol = order.Uint32(data[:4])
	offset := 4

	v.Services = order.Uint64(data[offset : offset+8])
	offset += 8

	sec := int64(order.Uint64(data[offset : offset+8]))
	v.Timestamp = time.Unix(sec, 0)
	offset += 8

	v.ToAddr, n = p2_addressInfoDecodeShort(data[offset:])
	offset += n

	v.FromAddr, n = p2_addressInfoDecodeShort(data[offset:])
	offset += n

	v.nonce = order.Uint64(data[offset : offset+8])
	offset += 8

	v.UserAgent, n = varStrDecode(data[offset:])
	offset += n

	v.Streams, _ = intListDecode(data[offset:])

	return v, nil
}

func (v *Version) p2_Encode() []byte {
	if v.protocol == 0 {
		v.protocol = ProtocolVersion
	}
	if v.nonce == 0 {
		v.nonce = RandNonce
	}

	data := packUint(order, v.protocol)
	data = append(data, packUint(order, v.Services)...)
	data = append(data, packUint(order, uint64(v.Timestamp.Unix()))...)
	data = append(data, v.ToAddr.p2_encodeShort()...)
	data = append(data, v.FromAddr.p2_encodeShort()...)
	data = append(data, packUint(order, v.nonce)...)
	data = append(data, varStrEncode(v.UserAgent)...)
	return append(data, intListEncode(v.Streams)...)
}

func p2_AddrDecode(data []byte) (a []*AddressInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			a = nil
			err = fmt.Errorf("payload: failed to decode addr payload (malformed)")
		}
	}()

	nAddr, offset := varIntDecode(data)
	a = make([]*AddressInfo, nAddr)
	for i := 0; i < nAddr; i++ {
		addr, n := p2_addressInfoDecode(data[offset:])
		a[i] = addr
		offset += n
	}
	return a, nil
}

func p2_AddrEncode(addresses ...*AddressInfo) []byte {
	data := varIntEncode(len(addresses))

	for _, addr := range addresses {
		data = append(data, addr.p2_encode()...)
	}
	return data
}

func p2_InventoryDecode(data []byte) (inv [][]byte, err error) {
	return byteListDecode("inv", data)
}

func p2_InventoryEncode(hashes [][]byte) []byte {
	return byteListEncode(hashes)
}

func p2_GetDataDecode(data []byte) (hashes [][]byte, err error) {
	return byteListDecode("getdata", data)
}

func p2_GetDataEncode(hashes [][]byte) []byte {
	return byteListEncode(hashes)
}

func p2_addressInfoDecode(data []byte) (v *AddressInfo, n int) {
	return &AddressInfo{
		Time:     time.Unix(int64(order.Uint64(data[:8])), 0),
		Stream:   int(order.Uint32(data[8:12])),
		Services: order.Uint64(data[12:20]),
		Ip:       unpackIp(data[20:36]),
		Port:     int(order.Uint16(data[36:38])),
	}, 38
}

func p2_addressInfoDecodeShort(data []byte) (v *AddressInfo, n int) {
	return &AddressInfo{
		//Stream:   int(order.Uint32(data[:4])),
		Services: order.Uint64(data[:8]),
		Ip:       unpackIp(data[8:24]),
		Port:     int(order.Uint16(data[24:26])),
	}, 26
}

func (ai *AddressInfo) p2_encode() []byte {
	data := make([]byte, 38)

	order.PutUint64(data[:8], uint64(ai.Time.Unix()))
	order.PutUint32(data[8:12], uint32(ai.Stream))
	order.PutUint64(data[12:20], ai.Services)
	packIp(data[20:36], ai.Ip)
	order.PutUint16(data[36:38], uint16(ai.Port))

	return data
}

func (ai *AddressInfo) p2_encodeShort() []byte {
	return ai.p2_encode()[12:]
}
