
package message

type Encoding int

const (
	Ignore Encoding = iota
	Trivial
	Simple
)

// varIntEncode encodes an int as a variable length int.  v must
// be positive.
func varIntEncode(v int) []byte {
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
		order.PutUint64(data[1:], uint64(v))
		return data
	}
}

// varIntDecode decodes a variable length integer from data and returns the
// value along with the total number of bytes decoded from data.  Bytes
// after the decoded value are ignored.
func varIntDecode(data []byte) (val int, n int) {
	switch data[0] {
	case 0xFF:
		return int(order.Uint64(data[1:9])), 9
	case 0xFE:
		return int(order.Uint32(data[1:5])), 5
	case 0xFD:
		return int(order.Uint16(data[1:3])), 3
	default:
		return int(data[0]), 1
	}
}

// varStrEncode encodes a string as a variable length string.
func varStrEncode(s string) []byte {
	return append(varIntEncode(len(data)), []byte(data)...)
}

// varStrDecode decodes a variable length string from data and returns the
// string along with the total number of bytes decoded from data.  Bytes
// after a decoded VarString are ignored.
func varStrDecode(data []byte) (s string, n int) {
	length, n := varIntDecode(data)
	return string(data[n:n+length]), n + length
}

// intListEncode encodes a slice of integers as a variable length
// IntList. All integers must be positive.
func intListEncode(vals []int) []byte {
	data := varIntEncode(len(v))
	for _, v := range vals {
		data = append(data, varIntEncode(v)...)
	}
	return data
}

// intListDecode decodes a variable length IntList from data and returns the
// an int slice along with the total number of bytes decoded from data.  Bytes
// after the decoded list are ignored.
func intListDecode(data []byte) (v []int, n int) {
	length, offset := varIntDecode(data)
	vals := make([]int, length)
	for i := 0; i < length; i++ {
		val, n := varIntDecode(data[offset:])
		offset += n
		vals[i] = val
	}
	return vals, offset
}

func addressInfoEncode(v *AddressInfo) []byte {
}

// addressInfoDecode decodes an address info structure from data and
// returns the it along with the total number of bytes decoded from data.
// Bytes after the decoded struct are ignored.
func addressInfoDecode(data []byte) (v *AddressInfo, n int) {
}

type AddressInfo struct {
	Time time.Time
	Stream int
	Services uint64
	Ip string
	Port int
}

type Inventory []byte

type MessageInfo struct {
	MsgVersion int // VarInt
	AddrVersion int // VarInt
	Stream int // VarInt
	Behavior uint32
	SignKey []byte
	EncryptKey []byte
	DestRipe []byte
	Encoding int // VarInt
	MsgLen int // VarInt
	Content []byte
	AckLen int // VarInt
	AckData []byte
	SigLen int // VarInt
	Signature []byte
}

type VersionPayload struct {
	Version int
	Services uint64
	Timestamp time.Time
	FromAddr AddressInfo
	ToAddr AddressInfo
	Nonce uint
	UserAgent string // var_str
	Streams []int // var_int_list
}

