package payload

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"testing"
)

func TestKeyEncode(t *testing.T) {
	expect, _ := hex.DecodeString("0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
	k, err := NewKey()
	if err != nil {
		t.Fatal("failed to create key")
	}

	data := elliptic.Marshal(k.Curve, k.Curve.Params().Gx, k.Curve.Params().Gy)

	if !bytes.Equal(data, expect) {
		t.Errorf("\nexpected: %x\n got: %x", expect, data)
	}
}
