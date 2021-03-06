package payload

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha1"
	_ "crypto/sha512"
	"encoding/asn1"
	"math"
	"math/big"
	mrand "math/rand"
	"time"

	"github.com/rwcarlsen/koblitz/kelliptic"
)

var signHash = crypto.SHA1
var powHash = crypto.SHA512

func getCurve() elliptic.Curve {
	return kelliptic.S256()
}

func FuzzyTime(giveTake time.Duration) time.Time {
	t := time.Now()
	fuzz := time.Duration((mrand.Float64()-0.5)*float64(giveTake)) * time.Second
	return t.Add(fuzz)
}

// DoPOW returns a proof of work nonce for data.
func DoPOW(trialsPerByte, extraLen int, data []byte) (nonce uint64) {
	h := powHash.New()
	h.Write(data)
	kernel := h.Sum(nil)

	trial := uint64(math.MaxUint64)
	target := math.MaxUint64 / uint64((len(data)+extraLen+8)*trialsPerByte)
	for trial > target {
		nonce++
		h.Reset()
		h.Write(append(packUint(order, nonce), kernel...))
		sum := h.Sum(nil)
		h.Reset()
		h.Write(sum)
		trial = order.Uint64(h.Sum(nil)[:8])
		if nonce == math.MaxUint64 {
			panic("payload: Failed to calculate POW")
		}
	}
	return nonce
}

func VerifyPOW(trialsPerByte, extraLen int, payload []byte) bool {
	h := powHash.New()

	h.Write(payload[8:])
	sum := h.Sum(nil)
	h.Reset()
	h.Write(payload[:8])
	h.Write(sum)
	sum = h.Sum(nil)
	h.Reset()
	h.Write(sum)
	sum = h.Sum(nil)

	pow := order.Uint64(sum[:8])
	return pow <= math.MaxUint64/uint64((len(payload)+extraLen)*trialsPerByte)
}

type Key struct {
	*ecdsa.PrivateKey
}

func NewKey() (*Key, error) {
	priv, err := ecdsa.GenerateKey(getCurve(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Key{priv}, nil
}

// Decode decodes a public key from data into k.
func DecodePubKey(data []byte) (k *Key, n int) {
	// PUBLIC KEY ONLY !!!
	x, y := elliptic.Unmarshal(getCurve(), data[:64])
	pub := ecdsa.PublicKey{getCurve(), x, y}
	return &Key{&ecdsa.PrivateKey{PublicKey: pub}}, 64
}

// Encode encodes the public key portion of this key.
func (k *Key) EncodePub() []byte {
	return elliptic.Marshal(k.Curve, k.X, k.Y)
}

func (k *Key) Verify(data, sig []byte) bool {
	h := signHash.New()
	h.Write(data)
	hash := h.Sum(nil)

	vals := signVals{}
	if _, err := asn1.Unmarshal(sig, &vals); err != nil {
		return false
	}

	return ecdsa.Verify(&k.PublicKey, hash, vals.R, vals.S)
}

type signVals struct {
	R, S *big.Int
}

// TODO: make sure hash and signature encoding are correct
func (k *Key) Sign(data []byte) (signature []byte, err error) {
	h := signHash.New()
	h.Write(data)
	hash := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, k.PrivateKey, hash)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(signVals{r, s})
}

func (k *Key) Encrypt(data []byte) []byte {
	panic("not implemented")
}

func (k *Key) Decrypt(data []byte) []byte {
	panic("not implemented")
}
