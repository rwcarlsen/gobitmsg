
package message

type Encoding int

const (
	Ignore Encoding = iota
	Trivial
	Simple
)

// VarIntEncode encodes an unsigned int as a variable length int.
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

// VarIntDecode decodes a variable length integer from data and returns the
// value along with the total number of bytes decoded from data.  Bytes
// after the decoded value are ignored.
func VarIntDecode(data []byte) (val uint64, n int) {
	switch data[0] {
	case 0xFF:
		return order.Uint64(data[1:9]), 9
	case 0xFE:
		return uint64(order.Uint32(data[1:5])), 5
	case 0xFD:
		return uint64(order.Uint16(data[1:3])), 3
	default:
		return uint64(data[0]), 1
	}
}

// VarStrEncode encodes a string as a variable length string
func VarStrEncode(s string) []byte {
	return append(VarIntEncode(uint64(len(data))), []byte(data)...)
}

// VarStrDecode decodes a variable length string from data and returns the
// string along with the total number of bytes decoded from data.  Bytes
// after a decoded VarString are ignored.
func VarStrDecode(data []byte) (s string, n int) {
	val, n := VarIntDecode(data)
	length := int(val)
	return string(data[n:n+length]), n + length
}

// IntListEncode encodes a slice of unsigned integers as a variable length
// IntList.
func IntListEncode(vals []uint64) []byte {
	data := VarIntEncode(uint64(len(v)))
	for _, v := range vals {
		data = append(data, VarIntEncode(v)...)
	}
	return data
}

// IntListDecode decodes a variable length IntList from data and returns the
// a uint slice along with the total number of bytes decoded from data.  Bytes
// after the decoded list are ignored.
func IntListDecode(data []byte) (v []uint64, n int) {
	v, offset := VarIntDecode(data)
	length := int(v)
	vals := make([]uint64, length)
	for i := 0; i < length; i++ {
		val, n := VarIntDecode(data[offset:])
		offset += n
		vals[i] = val
	}
	return vals, offset
}

func AddressInfoEncode(v *AddressInfo) []byte {
}

// AddressInfoDecode decodes an address info structure from data and
// returns the it along with the total number of bytes decoded from data.
// Bytes after the decoded struct are ignored.
func AddressInfoDecode(data []byte) (v *AddressInfo, n int) {
}

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

