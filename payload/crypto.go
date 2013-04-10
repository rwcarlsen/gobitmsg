package payload

import (
	"crypto/sha512"
	"math"
	"math/rand"
	"time"
)

// RandNonce is used to detect connections to self
var RandNonce = uint64(rand.Uint32())

func FuzzyTime(giveTake time.Duration) time.Time {
	t := time.Now()
	fuzz := time.Duration((rand.Float64()-0.5)*float64(giveTake)) * time.Second
	return t.Add(fuzz)
}

// proofOfWork returns a pow nonce for data.
func proofOfWork(data []byte) (nonce uint64) {
	h := sha512.New()
	h.Write(data)
	kernel := h.Sum(nil)

	trial := uint64(math.MaxUint64)
	target := math.MaxUint64 / ((uint64(len(data)) + PowExtraLen + 8) * PowTrialsPerByte)
	for nonce = 0; trial > target; nonce++ {
		h.Reset()
		h.Write(append(packUint(order, nonce), kernel...))
		h.Write(h.Sum(nil))
		trial = order.Uint64(h.Sum(nil)[:8])
		if nonce == math.MaxUint64 {
			panic("payload: Failed to calculate POW")
		}
	}
	return nonce
}

// Encrypt encrypts and signs data and returns the result.
// TODO: implement
func Encrypt(data []byte, encryptKey, signKey []byte) []byte {
	return data
}

// Decrypt decrypts data and returns the result.
// TODO: implement
func Decrypt(data []byte, encryptKey, signKey []byte) []byte {
	return data
}
