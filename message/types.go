
package message

type Encoding int

const (
	Ignore Encoding = iota
	Trivial
	Simple
)

func VarIntEncode(v uint64) []byte {
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
		order.PutUint64(data[1:], v)
		return data
	}
}

func VarIntDecode(data []byte) uint64 {
	switch data[0] {
	case 0xFF:
		return order.Uint64(data[1:])
	case 0xFE:
		return uint64(order.Uint32(data[1:]))
	case 0xFD:
		return uint64(order.Uint16(data[1:]))
	default:
		return uint64(data[0])
	}
}

type VarString string

func (v VarString) Val() string {
	return v
}

func (v VarString) Encode() []byte {

}

func (v *VarString) Decode(data []byte) {

}

type IntList []*VarInt

type AddressInfo struct {
	Time uint32
	Stream uint32
	Services uint64
	Ip []byte
	Port uint16
}

type Inventory []byte

type MessageInfo struct {
	MsgVersion uint64 // VarInt
	AddrVersion uint64 // VarInt
	Stream uint64 // VarInt
	Behavior uint32
	SignKey []byte
	EncryptKey []byte
	DestRipe []byte
	Encoding uint64 // VarInt
	MsgLen uint64 // VarInt
	Content []byte
	AckLen uint64 // VarInt
	AckData []byte
	SigLen uint64 // VarInt
	Signature []byte
}

type VersionPayload struct {
	Version uint64
	Services uint64
	Timestamp int64
	FromAddr AddressInfo
	ToAddr AddressInfo
	Nonce uint64
	UserAgent string // var_str
	Streams []uint64 // var_int_list
}

