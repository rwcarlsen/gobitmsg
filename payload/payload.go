package payload

import (
	"crypto/sha512"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
)

const (
	PowExtraLen      = 14000
	PowTrialsPerByte = 320
	DefaultFuzz      = 300 * time.Second
)

var order = msg.Order

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
		v.protocol = msg.ProtocolVersion
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
	Time        time.Time
	AddrVersion int
	Stream      int
	RipeHash    []byte
}

func GetPubKeyDecode(data []byte) *GetPubKey {
	g := &GetPubKey{}

	g.powNonce = order.Uint64(data[:8])
	offset := 8

	g.Time = time.Unix(int64(order.Uint64(data[offset:offset+8])), 0)
	offset += 8

	var n int
	g.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	g.Stream, n = varIntDecode(data[offset:])
	offset += n

	g.RipeHash = data[offset:]

	return g
}

func (g *GetPubKey) Encode() []byte {
	data := packUint(order, g.Time.Unix())
	data = append(data, varIntEncode(g.AddrVersion)...)
	data = append(data, varIntEncode(g.Stream)...)
	data = append(data, g.RipeHash...)

	if g.powNonce == 0 {
		g.powNonce = proofOfWork(PowTrialsPerByte, PowExtraLen, data)
	}
	return append(packUint(order, g.powNonce), data...)
}

func (g *GetPubKey) PowNonce() uint64 {
	return g.powNonce
}

type PubKey struct {
	powNonce      uint64
	Time          time.Time
	AddrVersion   int
	Stream        int
	Behavior      uint32
	SignKey       *Key
	EncryptKey    *Key
	TrialsPerByte int
	ExtraBytes    int
	SigLen        int
	signature     []byte // ECDSA from beginning through ExtraBytes
}

func PubKeyDecode(data []byte) *PubKey {
	k := &PubKey{}

	k.powNonce = order.Uint64(data[:8])
	offset := 8

	k.Time = time.Unix(int64(order.Uint64(data[offset:offset+8])), 0)
	offset += 8

	var n int
	k.AddrVersion, n = varIntDecode(data[offset:])
	offset += n

	k.Stream, n = varIntDecode(data[offset:])
	offset += n

	k.Behavior = order.Uint32(data[offset : offset+4])
	offset += 4

	k.SignKey, n = DecodeKey(data[offset:])
	offset += n

	k.EncryptKey, n = DecodeKey(data[offset:])
	offset += n

	k.TrialsPerByte, n = varIntDecode(data[offset:])
	offset += n

	k.ExtraBytes, n = varIntDecode(data[offset:])
	offset += n

	k.SigLen, n = varIntDecode(data[offset:])
	offset += n

	k.signature = append([]byte{}, data[offset:]...)

	return k
}

func (k *PubKey) Encode() []byte {
	data := packUint(order, k.Time.Unix())
	data = append(data, varIntEncode(k.AddrVersion)...)
	data = append(data, varIntEncode(k.Stream)...)
	data = append(data, packUint(order, k.Behavior)...)
	data = append(data, k.SignKey.Encode()...)
	data = append(data, k.EncryptKey.Encode()...)
	data = append(data, varIntEncode(k.TrialsPerByte)...)
	data = append(data, varIntEncode(k.ExtraBytes)...)

	if k.powNonce == 0 {
		k.powNonce = proofOfWork(PowTrialsPerByte, PowExtraLen, data)
	}
	data = append(packUint(order, k.powNonce), data...)

	var err error
	if k.signature, err = k.SignKey.Sign(data); err != nil {
		panic("signature failed")
	}
	data = append(data, varIntEncode(len(k.signature))...)
	data = append(data, k.signature...)

	return data
}

func (k *PubKey) Signature() []byte {
	return k.signature
}

func (k *PubKey) PowNonce() uint64 {
	return k.powNonce
}

type Message struct {
	powNonce uint64
	Time     time.Time
	// Stream is the destination/recipient's stream #
	Stream int
	Data   []byte
}

func MessageDecode(data []byte) *Message {
	m := &Message{}

	m.powNonce = order.Uint64(data[:8])
	offset := 8

	m.Time = time.Unix(int64(order.Uint64(data[offset:offset+8])), 0)
	offset += 8

	var n int
	m.Stream, n = varIntDecode(data[offset:])
	offset += n

	m.Data = data[offset:]

	return m
}

// NewMessage is a convenience function for creating a message with
// encrypted MsgInfo payload data.
func NewMessage(mi *MsgInfo, stream int) *Message {
	data := mi.Encode()
	encrypted := mi.EncryptKey.Encrypt(data)
	return &Message{
		Time:   FuzzyTime(DefaultFuzz),
		Stream: stream,
		Data:   encrypted,
	}
}

func (m *Message) Encode() []byte {
	data := packUint(order, m.Time.Unix())
	data = append(data, varIntEncode(m.Stream)...)
	data = append(data, m.Data...)

	if m.powNonce == 0 {
		m.powNonce = proofOfWork(PowTrialsPerByte, PowExtraLen, data)
	}
	return append(packUint(order, m.powNonce), data...)
}

func (m *Message) PowNonce() uint64 {
	return m.powNonce
}

type Broadcast struct {
	powNonce uint64
	Time     time.Time
	Version  int
	Stream   int
	Data     []byte
}

func BroadcastDecode(data []byte) *Broadcast {
	b := &Broadcast{}
	var n int

	b.powNonce = order.Uint64(data[:8])
	offset := 8

	b.Time = time.Unix(int64(order.Uint64(data[offset:offset+8])), 0)
	offset += 8

	b.Version, n = varIntDecode(data[offset:])
	offset += n

	b.Stream, n = varIntDecode(data[offset:])
	offset += n

	b.Data = data[offset:]

	return b
}

func (b *Broadcast) Encode() []byte {
	data := packUint(order, b.Time.Unix())
	data = append(data, varIntEncode(b.Version)...)
	data = append(data, varIntEncode(b.Stream)...)
	data = append(data, b.Data...)

	if b.powNonce == 0 {
		b.powNonce = proofOfWork(PowTrialsPerByte, PowExtraLen, data)
	}
	return append(packUint(order, b.powNonce), data...)
}

func (b *Broadcast) PowNonce() uint64 {
	return b.powNonce
}
