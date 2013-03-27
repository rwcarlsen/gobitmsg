
package payload

import (
	"time"

	"github.com/rwcarlsen/gobitmst/payload"
)

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

