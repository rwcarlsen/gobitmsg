package payload

import (
	"crypto/sha512"
	"math/rand"
	"time"

	"github.com/rwcarlsen/gobitmsg/message"
)

const (
	PowExtraLen      = 14000
	PowTrialsPerByte = 320
)

var order = message.Order

// RandNonce is used to detect connections to self
var RandNonce = uint64(rand.Uint32())

func fuzzTime() time.Time {
	t := time.Now()
	fuzz := time.Duration((rand.Float64()-0.5)*300) * time.Second
	return t.Add(fuzz)
}

// proofOfWork returns a pow nonce for data.
func proofOfWork(data []byte) (nonce uint64, err error) {
	h := sha512.New()
	h.Write(data)
	kernel := h.Sum(nil)

	trial := math.MaxUint64
	target := math.MaxUint64 / ((len(data) + PowExtraLen + 8) * PowTrialsPerByte)
	for nonce = 0; trial > target; nonce++ {
		h.Reset()
		h.Write(append(packUint(order, nonce), kernel...))
		h.Write(h.Sum(nil))
		sum := h.Sum(nil)
		trial = order.Uint64(sum[len(sum)-8 : len(sum)])
		if nonce == math.MaxUint64 {
			return 0, errors.New("payload: Failed to calculate POW")
		}
	}
	return nonce, nil
}

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

func NewVersion(userAgent string, streams []int, from, to *AddressInfo) *Version {
	return &Version{
		Ver:       message.ProtocolVersion,
		Services:  1,
		Timestamp: time.Now(),
		ToAddr:    to,
		FromAddr:  from,
		Nonce:     RandNonce,
		UserAgent: userAgent,
		Streams:   streams,
	}
}

func (v *Version) Encode() []byte {
	data := packUint(order, uint32(v.Ver))
	data = append(data, packUint(order, v.Services)...)
	data = append(data, packUint(order, v.Timestamp.Unix())...)
	data = append(data, v.ToAddr.encodeShort()...)
	data = append(data, v.FromAddr.encodeShort()...)
	data = append(data, packUint(order, v.Nonce)...)
	data = append(data, varStrEncode(v.UserAgent)...)
	data = append(data, intListEncode(v.Streams)...)
	return data
}

func (v *Version) Decode(data []byte) {
	v.Ver = int(order.Uint32(data[:4]))
	offset := 4

	v.Services = order.Uint64(data[offset : offset+8])
	offset += 8

	sec = order.Uint64(data[offset : offset+8])
	v.Timestamp = time.Unix(sec, 0)
	offset += 8

	v.ToAddr, n = addressInfoDecodeShort(data[offset:])
	offset += n

	v.FromAddr, n = addressInfoDecodeShort(data[offset:])
	offset += n

	v.Nonce = order.Uint64(data[offset : offset+8])
	offset += 8

	v.UserAgent, n = varStrDecode(data[offset:])
	offset += n

	v.Streams, _ = intListDecode(data[offset:])
}

func AddrEncode(addresses []*AddressInfo) []byte {
	data := varIntEncode(len(addresses))

	for _, addr := range addresses {
		data = append(data, addressInfoEncode(addr)...)
	}
}

func AddrDecode(data []byte) []*AddressInfo {
	nAddr, offset := varIntDecode(data)
	addresses = make([]*AddressInfo, nAddr)
	for i := 0; i < nAddr; i++ {
		addr, n := addressInfoDecode(data[offset:])
		addresses[i] = addr
		offset += n
	}
	return addresses
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

func InventoryDecode(data []byte) [][]byte {
	nObj, offset := varIntDecode(data)
	objData = make([][]byte, nObj)
	for i := 0; i < nObj; i++ {
		start := offset + i*32
		end := start + 32
		objData = append(objData, data[start:end])
	}
	return objData
}

func GetDataEncode(hashes [][]byte) []byte {
	data := varIntEncode(len(hashes))
	for _, sum := range hashes {
		data = append(data, sum...)
	}
	return data
}

func GetDataDecode(data []byte) [][]byte {
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

func (g *GetPubKey) Encode() []byte {
	data := packUint(order, g.PowNonce)
	data = append(data, packUint(order, uint32(g.Time.Unix()))...)
	data = append(data, varIntEncode(g.AddrVersion)...)
	data = append(data, varIntEncode(g.Stream)...)
	data = append(data, g.RipeHash...)
	return data
}

func (g *GetPubKey) Decode(data []byte) {
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

func (k *PubKey) Encode() []byte {
	data := packUint(order, k.PowNonce)
	data = append(data, packUint(order, uint32(k.Time.Unix()))...)
	data = append(data, varIntEncode(k.AddrVersion)...)
	data = append(data, varIntEncode(k.Stream)...)
	data = append(data, packUint(order, k.Behavior)...)
	data = append(data, k.SignKey...)
	data = append(data, k.EncryptKey...)
	return data
}

func (k *PubKey) Decode(data []byte) {
	k.PowNonce = order.Uint64(data[:8])
	offset := 8

	k.Time = time.Unix(order.Uint64(data[offset:offset+4]), 0)
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
}

type Message struct {
	PowNonce uint64
	Time     time.Time
	Stream   int
	Data     []byte
}

func (m *Message) Encode() []byte {
	data := packUint(order, m.PowNonce)
	data = append(data, packUint(order, uint32(m.Time.Unix()))...)
	data = append(data, varIntEncode(m.Stream)...)
	data = append(data, m.Data...)

	return data
}

func (m *Message) Decode(data []byte) {
	m.PowNonce = order.Uint64(data[:8])
	offset := 8

	m.Time = time.Unix(order.Uint64(data[offset:offset+4]), 0)
	offset += 4

	var n int
	k.Stream, n = varIntDecode(data[offset:])
	offset += n

	m.Data = data[offset:]
}

type Broadcast struct {
	PowNonce         uint64
	Time             time.Time // uint32
	BroadcastVersion int       // var_int
	AddrVersion      int       // var_int
	Stream           int       // var_int
	Behavior         uint32
	SignKey          []byte // len=64
	EncryptKey       []byte // len=64
	AddrHash         []byte // len=120
	Encoding         int    // var_int
	MsgLen           int    // var_int
	Msg              []byte
	SigLen           int // var_int
	Signature        []byte
}
