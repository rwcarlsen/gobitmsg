package payload

import (
	"time"
)

const (
	PowExtraLen      = 14000
	PowTrialsPerByte = 320
	DefaultFuzz      = 300 * time.Second
)

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

	k.SignKey, n = DecodePubKey(data[offset:])
	offset += n

	k.EncryptKey, n = DecodePubKey(data[offset:])
	offset += n

	k.TrialsPerByte, n = varIntDecode(data[offset:])
	offset += n

	k.ExtraBytes, n = varIntDecode(data[offset:])
	offset += n

	_, n = varIntDecode(data[offset:])
	offset += n

	k.signature = append([]byte{}, data[offset:]...)

	return k
}

func (k *PubKey) Encode() []byte {
	data := packUint(order, k.Time.Unix())
	data = append(data, varIntEncode(k.AddrVersion)...)
	data = append(data, varIntEncode(k.Stream)...)
	data = append(data, packUint(order, k.Behavior)...)
	data = append(data, k.SignKey.EncodePub()...)
	data = append(data, k.EncryptKey.EncodePub()...)
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

const BroadcastVersion = 2

type Broadcast struct {
	powNonce uint64
	Time     time.Time
	version  int
	Stream   int
	Data     []byte
}

// NewBroadcast is a convenience function for creating a broadcast message with
// encrypted BroadcastInfo payload data.
func NewBroadcast(bi *BroadcastInfo, stream int) *Broadcast {
	data := bi.Encode()
	encrypted := bi.EncryptKey.Encrypt(data)
	return &Broadcast{
		Time:    FuzzyTime(DefaultFuzz),
		Stream:  stream,
		Data:    encrypted,
		version: BroadcastVersion,
	}
}

func BroadcastDecode(data []byte) *Broadcast {
	b := &Broadcast{}
	var n int

	b.powNonce = order.Uint64(data[:8])
	offset := 8

	b.Time = time.Unix(int64(order.Uint64(data[offset:offset+8])), 0)
	offset += 8

	b.version, n = varIntDecode(data[offset:])
	offset += n

	b.Stream, n = varIntDecode(data[offset:])
	offset += n

	b.Data = data[offset:]

	return b
}

func (b *Broadcast) Encode() []byte {
	data := packUint(order, b.Time.Unix())
	data = append(data, varIntEncode(b.version)...)
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

func (b *Broadcast) Version() int {
	return b.version
}
