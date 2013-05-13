package payload

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
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

func TestVerify(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal("failed to create key")
	}

	d := "60664f040d5d4e5202f89724cdaec68a94fd022481ceee5e57ed7d80208249"
	x := "7cfd8299a6c4e357a86acb9e39250c82d1e7329fa89e0bb8854c699a5d3c080e"
	y := "9f707fb325ef0fd4eb24250a427a4a2ce54645bdeb27b1cb63c15f5349f7f8ec"
	k.D, _ = new(big.Int).SetString(d, 16)
	k.X, _ = new(big.Int).SetString(x, 16)
	k.Y, _ = new(big.Int).SetString(y, 16)

	data := []byte("hello")
	sigs := []string{
		"304502204a8d238fbd74639790c5282c8da79c83a518e1e5ea520271a39624c3e1eb3f68022100abadb64f9f45d036e89b775938bda8ee8d0f80a78d72fa72c45b71209aedae8e",
		"3045022100998555e3a7586f2f44aee20de7cb1930f9cf4358a415c4a032d8eb12ca5d210f02203cb1eed05383e11f9ffd07acaadd26ea733bc4bde37e80f6d18cfc54128ae857",
		"30450220712c00262b21ffd7c5f98d353bd9427af6f4d4e5065bb87cbf7f18dc8fa0a2c602210083e830de1a7250a9dbe678b023601b1b78f1f5da125e6f4f52c43cd0ff1fccfc",
	}

	for i, s := range sigs {
		sig, _ := hex.DecodeString(s)
		if !k.Verify(data, sig) {
			t.Errorf("Failed to verify signature %v", i)
		}
	}
}

func TestSign(t *testing.T) {
	k, err := NewKey()
	if err != nil {
		t.Fatal("failed to create key")
	}

	data := []byte("hello")

	sig, err := k.Sign(data)
	if err != nil {
		t.Error("failed to sign data")
	} else if !k.Verify(data, sig) {
		t.Error("failed to verify own signature")
	}
}
