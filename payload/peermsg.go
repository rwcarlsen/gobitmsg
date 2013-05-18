package payload

import (
	"fmt"
	"math/rand"
	"strconv"
	"time"

	"github.com/rwcarlsen/gobitmsg/msg"
)

var order = msg.Order

const ProtocolVersion = 2

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
	switch proto := order.Uint32(data[:4]); proto {
	case 1:
		return p1_VersionDecode(data)
	case 2:
		return p2_VersionDecode(data)
	default:
		return nil, fmt.Errorf("payload: cannot decode unsupport protocol version %v", proto)
	}
}

func (v *Version) Encode(proto uint32) ([]byte, error) {
	switch proto {
	case 1:
		return v.p1_Encode(), nil
	case 2:
		return v.p2_Encode(), nil
	default:
		return nil, fmt.Errorf("payload: cannot encode unsupport protocol version %v", proto)
	}
}

func (v *Version) Protocol() uint32 {
	return v.protocol
}

func (v *Version) Nonce() uint64 {
	return v.nonce
}

func AddrDecode(proto uint32, data []byte) (a []*AddressInfo, err error) {
	switch proto {
	case 1:
		return p1_AddrDecode(data)
	case 2:
		return p2_AddrDecode(data)
	default:
		return nil, fmt.Errorf("payload: cannot decode unsupport protocol version %v", proto)
	}
}

func AddrEncode(proto uint32, addresses ...*AddressInfo) ([]byte, error) {
	switch proto {
	case 1:
		return p1_AddrEncode(addresses...), nil
	case 2:
		return p2_AddrEncode(addresses...), nil
	default:
		return nil, fmt.Errorf("payload: cannot encode unsupport protocol version %v", proto)
	}
}

func InventoryDecode(proto uint32, data []byte) (inv [][]byte, err error) {
	switch proto {
	case 1:
		return p1_InventoryDecode(data)
	case 2:
		return p2_InventoryDecode(data)
	default:
		return nil, fmt.Errorf("payload: cannot decode unsupport protocol version %v", proto)
	}
}

func InventoryEncode(proto uint32, hashes [][]byte) ([]byte, error) {
	switch proto {
	case 1:
		return p1_InventoryEncode(hashes), nil
	case 2:
		return p2_InventoryEncode(hashes), nil
	default:
		return nil, fmt.Errorf("payload: cannot encode unsupport protocol version %v", proto)
	}
}

func GetDataDecode(proto uint32, data []byte) (hashes [][]byte, err error) {
	switch proto {
	case 1:
		return p1_GetDataDecode(data)
	case 2:
		return p2_GetDataDecode(data)
	default:
		return nil, fmt.Errorf("payload: cannot decode unsupport protocol version %v", proto)
	}
}

func GetDataEncode(proto uint32, hashes [][]byte) ([]byte, error) {
	switch proto {
	case 1:
		return p1_GetDataEncode(hashes), nil
	case 2:
		return p2_GetDataEncode(hashes), nil
	default:
		return nil, fmt.Errorf("payload: cannot encode unsupport protocol version %v", proto)
	}
}

type AddressInfo struct {
	Time     time.Time
	Stream   int
	Services uint64
	Ip       string
	Port     int
}

func (ai *AddressInfo) Addr() string {
	p := strconv.Itoa(ai.Port)
	return fmt.Sprintf("%v:%v", ai.Ip, p)
}
