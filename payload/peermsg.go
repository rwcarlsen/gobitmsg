package payload

import (
	"crypto/sha512"
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
)

var order = msg.Order

// RandNonce is used in Version messages to detect connections to self
var RandNonce = uint64(rand.Uint32())

type Version struct {
	protocol  uint32
	Services  uint64
	Timestamp time.Time
	ToAddr    *AddressInfo
	FromAddr  *AddressInfo
	nonce     uint64
	UserAgent string
	Streams   []int
}

func VersionDecode(data []byte) (v *Version, err error) {
	defer func() {
		if r := recover(); r != nil {
			v = nil
			err = fmt.Errorf("payload: failed to decode version payload (malformed)")
		}
	}()

	v = &Version{}

	v.protocol = order.Uint32(data[:4])
	offset := 4

	v.Services = order.Uint64(data[offset : offset+8])
	offset += 8

	sec := int64(order.Uint64(data[offset : offset+8]))
	v.Timestamp = time.Unix(sec, 0)
	offset += 8

	var n int
	v.ToAddr, n = addressInfoDecodeShort(data[offset:])
	offset += n

	v.FromAddr, n = addressInfoDecodeShort(data[offset:])
	offset += n

	v.nonce = order.Uint64(data[offset : offset+8])
	offset += 8

	v.UserAgent, n = varStrDecode(data[offset:])
	offset += n

	v.Streams, _ = intListDecode(data[offset:])

	return v, nil
}

func (v *Version) Encode() []byte {
	if v.protocol == 0 {
		v.protocol = msg.ProtocolVersion
	}
	if v.nonce == 0 {
		v.nonce = RandNonce
	}

	data := packUint(order, v.protocol)
	data = append(data, packUint(order, v.Services)...)
	data = append(data, packUint(order, uint64(v.Timestamp.Unix()))...)
	data = append(data, v.ToAddr.encodeShort()...)
	data = append(data, v.FromAddr.encodeShort()...)
	data = append(data, packUint(order, v.nonce)...)
	data = append(data, varStrEncode(v.UserAgent)...)
	return append(data, intListEncode(v.Streams)...)
}

func (v *Version) Protocol() uint32 {
	return v.protocol
}

func (v *Version) Nonce() uint64 {
	return v.nonce
}

func AddrDecode(data []byte) (a []*AddressInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			a = nil
			err = fmt.Errorf("payload: failed to decode addr payload (malformed)")
		}
	}()

	nAddr, offset := varIntDecode(data)
	a = make([]*AddressInfo, nAddr)
	for i := 0; i < nAddr; i++ {
		addr, n := addressInfoDecode(data[offset:])
		a[i] = addr
		offset += n
	}
	return a, nil
}

func AddrEncode(addresses ...*AddressInfo) []byte {
	data := varIntEncode(len(addresses))

	for _, addr := range addresses {
		data = append(data, addr.encode()...)
	}
	return data
}

func InventoryDecode(data []byte) (inv [][]byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			inv = nil
			err = fmt.Errorf("payload: failed to decode inv payload (malformed)")
		}
	}()

	nObj, offset := varIntDecode(data)
	objData := make([][]byte, nObj)
	for i := 0; i < nObj; i++ {
		start := offset + i*32
		end := start + 32
		objData[i] = data[start:end]
	}
	return objData, nil
}

func InventoryEncode(objData [][]byte) []byte {
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

func GetDataDecode(data []byte) (hashes [][]byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			hashes = nil
			err = fmt.Errorf("payload: failed to decode getdata payload (malformed)")
		}
	}()

	nHashes, offset := varIntDecode(data)
	hashes = make([][]byte, nHashes)
	for i := 0; i < nHashes; i++ {
		start := offset + i*32
		end := start + 32
		hashes = append(hashes, data[start:end])
	}
	return hashes, nil
}

func GetDataEncode(hashes [][]byte) []byte {
	data := varIntEncode(len(hashes))
	for _, sum := range hashes {
		data = append(data, sum...)
	}
	return data
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
		Time:     time.Unix(int64(order.Uint64(data[:8])), 0),
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
	data := make([]byte, 38)

	order.PutUint64(data[:8], uint64(ai.Time.Unix()))
	order.PutUint32(data[4:8], uint32(ai.Stream))
	order.PutUint64(data[8:16], ai.Services)
	packIp(data[16:32], ai.Ip)
	order.PutUint16(data[32:34], uint16(ai.Port))

	return data
}

func (ai *AddressInfo) encodeShort() []byte {
	return ai.encode()[12:]
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
