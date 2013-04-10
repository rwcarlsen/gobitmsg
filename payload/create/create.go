// Package create provides convenience functions for creating certain message
// payloads.
package create

import (
	"math/rand"
	"time"

	"github.com/rwcarlsen/gobitmsg/payload"
)

// RandNonce is used to detect connections to self
var RandNonce = uint64(rand.Uint32())

func FuzzyTime(giveTake time.Duration) time.Time {
	t := time.Now()
	fuzz := time.Duration((rand.Float64()-0.5)*float64(giveTake)) * time.Second
	return t.Add(fuzz)
}

// Encrypt encrypts and signs data using the provided elliptic keys
// TODO: implement
func Encrypt(data []byte, encryptKey, signKey []byte) []byte {
	return data
}

func Version(userAgent string, services uint64, streams []int, from, to *payload.AddressInfo) *payload.Version {
	return &payload.Version{
		Services:  services,
		Timestamp: time.Now(),
		ToAddr:    to,
		FromAddr:  from,
		Nonce:     RandNonce,
		UserAgent: userAgent,
		Streams:   streams,
	}
}

func GetPubKey(addrVer, stream int, ripe []byte) *payload.GetPubKey {
	return &payload.GetPubKey{
		Time:        FuzzyTime(),
		AddrVersion: addrVer,
		Stream:      stream,
		RipeHash:    ripe,
	}
}

func PubKey(addrVer, stream int, behavior uint32, signKey, encryptKey []byte) *payload.PubKey {
	return &payload.PubKey{
		Time:        FuzzyTime(),
		AddrVersion: addrVer,
		Stream:      stream,
		Behavior:    behavior,
		SignKey:     signKey,
		EncryptKey:  encryptKey,
	}
}

type Message struct {
	powNonce uint64
	Time     time.Time
	Stream   int
	Data     []byte
}

type MsgInfo struct {
	MsgVersion  int // VarInt
	AddrVersion int // VarInt
	Stream      int // VarInt
	Behavior    uint32
	SignKey     []byte
	EncryptKey  []byte
	DestRipe    []byte
	Encoding    int // VarInt
	MsgLen      int // VarInt
	Content     []byte
	AckLen      int // VarInt
	AckData     []byte
	SigLen      int // VarInt
	Signature   []byte
}

func Message(ver, addrVer, stream, encoding int, behavior uint32, signKey, encryptKey, dest, content, ack []byte) []byte {
	info := &payload.MsgInfo{
		MsgVersion: ver
		AddrVersion: addrVer,
		Stream: stream,
		Behavior: behavior,
		SignKey: signKey,
		EncryptKey: encryptKey,
		DestRipe: dest,
		Encoding: encoding
		MsgLen: len(content),
		Content: content,
		AckLen: len(ack),
		AckData: ack,
	}

	m := &payload.Message{
		Time: FuzzyTime(),
		Stream: stream,
	}

}

