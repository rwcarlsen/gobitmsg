package buildmsg

import (
	"math/rand"
	"time"

	"github.com/rwcarlsen/gobitmsg/message"
	"github.com/rwcarlsen/gobitmsg/payload"
)

// RandNonce is used to detect connections to self
var RandNonce = uint64(rand.Uint32())

func fuzzTime() time.Time {
	t := time.Now()
	fuzz := time.Duration((rand.Float64()-0.5)*300) * time.Second
	return t.Add(fuzz)
}

func Version(userAgent string, streams []int, from, to *payload.AddressInfo) []byte {
	v := &payload.Version{
		Ver:       message.ProtocolVersion,
		Services:  1,
		Timestamp: time.Now(),
		ToAddr:    to,
		FromAddr:  from,
		Nonce:     RandNonce,
		UserAgent: userAgent,
		Streams:   streams,
	}
	return v.Encode()
}

func GetPubKey(addrVer, stream int, ripe []byte) []byte {
	g := &payload.GetPubKey{
		Time:        fuzzTime(),
		AddrVersion: addrVer,
		Stream:      stream,
		RipeHash:    ripe,
	}

	return g.Encode()
}

func PubKey(addrVer, stream int, behavior uint32, signKey, encryptKey []byte) []byte {
	return nil
}
