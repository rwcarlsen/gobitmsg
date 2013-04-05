package payload

import (
	"crypto/sha512"
	"math"
	"time"

	"github.com/rwcarlsen/gobitmsg/message"
)

const (
	PowExtraLen      = 14000
	PowTrialsPerByte = 320
)

var order = message.Order

// proofOfWork returns a pow nonce for data.
func proofOfWork(data []byte) (nonce uint64) {
	h := sha512.New()
	h.Write(data)
	kernel := h.Sum(nil)

	trial := uint64(math.MaxUint64)
	target := math.MaxUint64 / ((uint64(len(data)) + PowExtraLen + 8) * PowTrialsPerByte)
	for nonce = 0; trial > target; nonce++ {
		h.Reset()
		h.Write(append(packUint(order, nonce), kernel...))
		h.Write(h.Sum(nil))
		sum := h.Sum(nil)
		trial = order.Uint64(sum[len(sum)-8 : len(sum)])
		if nonce == math.MaxUint64 {
			panic("payload: Failed to calculate POW")
		}
	}
	return nonce
}

type Version struct {
	protocol  uint32
	Services  uint64
	Timestamp time.Time    // Unix int64
	ToAddr    *AddressInfo // short (w/o time and stream)
	FromAddr  *AddressInfo // short (w/o time and stream)
	Nonce     uint64
	UserAgent string // var_str
	Streams   []int  // var_int_list
}

func VersionDecode(data []byte) *Version {
	v := &Version{}

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

	v.Nonce = order.Uint64(data[offset : offset+8])
	offset += 8

	v.UserAgent, n = varStrDecode(data[offset:])
	offset += n

	v.Streams, _ = intListDecode(data[offset:])

	return v
}

func (v *Version) Encode() []byte {
	if v.protocol == 0 {
		v.protocol = message.ProtocolVersion
	}

	data := packUint(order, v.protocol)
	data = append(data, packUint(order, v.Services)...)
	data = append(data, packUint(order, uint64(v.Timestamp.Unix()))...)
	data = append(data, v.ToAddr.encodeShort()...)
	data = append(data, v.FromAddr.encodeShort()...)
	data = append(data, packUint(order, v.Nonce)...)
	data = append(data, varStrEncode(v.UserAgent)...)
	return append(data, intListEncode(v.Streams)...)
}

func (v *Version) Protocol() uint32 {
	return v.protocol
}

func AddrDecode(data []byte) []*AddressInfo {
	nAddr, offset := varIntDecode(data)
	addresses := make([]*AddressInfo, nAddr)
	for i := 0; i < nAddr; i++ {
		addr, n := addressInfoDecode(data[offset:])
		addresses[i] = addr
		offset += n
	}
	return addresses
}

func AddrEncode(addresses ...*AddressInfo) []byte {
	data := varIntEncode(len(addresses))

	for _, addr := range addresses {
		data = append(data, addr.encode()...)
	}
	return data
}

func InventoryDecode(data []byte) [][]byte {
	nObj, offset := varIntDecode(data)
	objData := make([][]byte, nObj)
	for i := 0; i < nObj; i++ {
		start := offset + i*32
		end := start + 32
		objData[i] = data[start:end]
	}
	return objData
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

func GetDataDecode(data []byte) [][]byte {
	nHashes, offset := varIntDecode(data)
	hashes := make([][]byte, nHashes)
	for i := 0; i < nHashes; i++ {
		start := offset + i*32
		end := start + 32
		hashes = append(hashes, data[start:end])
	}
	return hashes
}

func GetDataEncode(hashes [][]byte) []byte {
	data := varIntEncode(len(hashes))
	for _, sum := range hashes {
		data = append(data, sum...)
	}
	return data
}

type GetPubKey struct {
	powNonce    uint64
	Time        time.Time // uint32
	AddrVersion int       // var_int
	Stream      int       // var_int
	RipeHash    []byte    // len=20
}

func GetPubKeyDecode(data []byte) *GetPubKey {
	g := &GetPubKey{}

	g.powNonce = order.Uint64(data[:8])
	offset := 8

	g.Time = time.Unix(int64(order.Uint32(data[offset:offset+4])), 0)
	offset += 4

	var n int
	g.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	g.Stream, n = varIntDecode(data[offset:])
	offset += n

	g.RipeHash = data[offset:]

	return g
}

func (g *GetPubKey) Encode() []byte {
	data := packUint(order, uint32(g.Time.Unix()))
	data = append(data, varIntEncode(g.AddrVersion)...)
	data = append(data, varIntEncode(g.Stream)...)
	data = append(data, g.RipeHash...)

	if g.powNonce == 0 {
		g.powNonce = proofOfWork(data)
	}
	return append(packUint(order, g.powNonce), data...)
}

func (g *GetPubKey) PowNonce() uint64 {
	return g.powNonce
}

type PubKey struct {
	powNonce    uint64
	Time        time.Time // uint32
	AddrVersion int       // var_int
	Stream      int       // var_int
	Behavior    uint32    // bitfield
	SignKey     []byte    // len=64
	EncryptKey  []byte    // len=64
}

func PubKeyDecode(data []byte) *PubKey {
	k := &PubKey{}

	k.powNonce = order.Uint64(data[:8])
	offset := 8

	k.Time = time.Unix(int64(order.Uint32(data[offset:offset+4])), 0)
	offset += 4

	var n int
	k.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	k.Stream, n = varIntDecode(data[offset:])
	offset += n

	k.Behavior = order.Uint32(data[offset : offset+4])
	offset += 4

	k.SignKey = data[offset : offset+64]
	offset += 64

	k.EncryptKey = data[offset : offset+64]

	return k
}

func (k *PubKey) Encode() []byte {
	data := packUint(order, uint32(k.Time.Unix()))
	data = append(data, varIntEncode(k.AddrVersion)...)
	data = append(data, varIntEncode(k.Stream)...)
	data = append(data, packUint(order, k.Behavior)...)
	data = append(data, k.SignKey...)
	data = append(data, k.EncryptKey...)

	if k.powNonce == 0 {
		k.powNonce = proofOfWork(data)
	}
	return append(packUint(order, k.powNonce), data...)
}

func (k *PubKey) PowNonce() uint64 {
	return k.powNonce
}

type Message struct {
	powNonce uint64
	Time     time.Time
	Stream   int
	Data     []byte
}

func MessageDecode(data []byte) *Message {
	m := &Message{}

	m.powNonce = order.Uint64(data[:8])
	offset := 8

	m.Time = time.Unix(int64(order.Uint32(data[offset:offset+4])), 0)
	offset += 4

	var n int
	m.Stream, n = varIntDecode(data[offset:])
	offset += n

	m.Data = data[offset:]

	return m
}

func (m *Message) Encode() []byte {
	data := packUint(order, uint32(m.Time.Unix()))
	data = append(data, varIntEncode(m.Stream)...)
	data = append(data, m.Data...)

	if m.powNonce == 0 {
		m.powNonce = proofOfWork(data)
	}
	return append(packUint(order, m.powNonce), data...)
}

func (m *Message) PowNonce() uint64 {
	return m.powNonce
}

type Broadcast struct {
	powNonce         uint64
	Time             time.Time // uint32
	BroadcastVersion int       // var_int
	AddrVersion      int       // var_int
	Stream           int       // var_int
	Behavior         uint32
	SignKey          []byte // len=64
	EncryptKey       []byte // len=64
	AddrHash         []byte // len=20
	Encoding         int    // var_int
	MsgLen           int    // var_int
	Msg              []byte
	SigLen           int // var_int
	Signature        []byte
}

func BroadcastDecode(data []byte) *Broadcast {
	b := &Broadcast{}
	var n int

	b.powNonce = order.Uint64(data[:8])
	offset := 8

	b.Time = time.Unix(int64(order.Uint32(data[offset:offset+4])), 0)
	offset += 4

	b.BroadcastVersion, n = varIntDecode(data[offset:])
	offset += n

	b.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	b.Stream, n = varIntDecode(data[offset:])
	offset += n

	b.Behavior = order.Uint32(data[offset : offset+4])
	offset += 4

	b.SignKey = append([]byte{}, data[offset:offset+64]...)
	offset += 64

	b.EncryptKey = append([]byte{}, data[offset:offset+64]...)
	offset += 64

	b.AddrHash = append([]byte{}, data[offset:offset+20]...)
	offset += 20

	b.Encoding, n = varIntDecode(data[offset:])
	offset += n

	b.MsgLen, n = varIntDecode(data[offset:])
	offset += n

	b.Msg = append([]byte{}, data[offset:offset+b.MsgLen]...)
	offset += b.MsgLen

	b.SigLen, n = varIntDecode(data[offset:])
	offset += n

	b.Signature = append([]byte{}, data[offset:offset+b.SigLen]...)

	return b
}

func (b *Broadcast) Encode() []byte {
	data := packUint(order, uint32(b.Time.Unix()))
	data = append(data, varIntEncode(b.BroadcastVersion)...)
	data = append(data, varIntEncode(b.AddrVersion)...)
	data = append(data, varIntEncode(b.Stream)...)
	data = append(data, packUint(order, b.Behavior)...)
	data = append(data, b.SignKey...)
	data = append(data, b.EncryptKey...)
	data = append(data, b.AddrHash...)
	data = append(data, varIntEncode(b.Encoding)...)
	data = append(data, varIntEncode(b.MsgLen)...)
	data = append(data, b.Msg...)
	data = append(data, varIntEncode(b.SigLen)...)
	data = append(data, b.Signature...)

	if b.powNonce == 0 {
		b.powNonce = proofOfWork(data)
	}
	return append(packUint(order, b.powNonce), data...)
}

func (b *Broadcast) PowNonce() uint64 {
	return b.powNonce
}
