package payload

import (
	"crypto/sha512"
	"crypto/ecdsa"
	"crypto/rand"
	"math"
	"math/rand"
	"math/big"
	"time"
	"encoding/ans1"

	"github.com/rwcarlsen/koblitz/kelliptic"
)

var curve

func getCurve() *elliptic.CurveParams {
}

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

type Key struct {
	 key *ecdsa.PrivateKey
}

func NewKey() (*Key, error) {
	curve := kelliptic.S256()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{key: priv}
}

// Decode decodes a public key.
func DecodeKey(data []byte) (k *Key, n int) {
	// only 64 bytes long
	// PUBLIC KEY ONLY !!!
	panic("not implemented")
}

// Encode encodes the public key.
func (k *Key) Encode() []byte {
	// only 64 bytes long
	// PUBLIC KEY ONLY !!!
	panic("not implemented")
}

func (k *Key) Verify(data, sig []byte) bool {
	panic("not implemented")
}

// TODO: make sure hash and signature encoding are correct
func (k *Key) Sign(data []byte) (signature []byte, err error) {
	h := sha512.New()
	h.Write(data)
	hash := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, k.key, hash)
	if err != nil {
		return nil, err
	}
	return ans1.Marshal(struct{R, S *big.Int}{r, s})
}

func (k *Key) Encrypt(data []byte) []byte {
	panic("not implemented")
}

func (k *Key) Decrypt(data []byte) []byte {
	panic("not implemented")
}

