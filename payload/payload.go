
package payload

import (
	"time"
)

type Version struct {
	Ver int
	Services uint64
	Timestamp time.Time
	FromAddr *AddressInfo
	ToAddr *AddressInfo
	Nonce uint
	UserAgent string // var_str
	Streams []int // var_int_list
}

func EncodeVersion(v *Version) []byte {

}

func DecodeVersion(data []byte) *Version {

}

