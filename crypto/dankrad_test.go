package crypto

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

func BenchmarkECMul(b *testing.B) {
	curve := secp256k1.S256()

	var err error
	scalars := make([]*big.Int, 10000)
	for i := range scalars {
		scalars[i], err = rand.Int(rand.Reader, curve.Params().P)
		if err != nil {
			b.Fatal(err)
		}
	}
	scalarBytes := make([][]byte, 10000)
	for i := range scalars {
		scalarBytes[i] = scalars[i].Bytes()
	}

	b.Run("alt_bn128", func(b *testing.B) {
		val := new(bn256.G1)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, s := range scalars {
				val.ScalarMult(val, s)
			}
		}
	})

	b.Run("secp256k1", func(b *testing.B) {
		gx, gy := curve.Gx, curve.Gy

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			for _, s := range scalarBytes {
				gx, gy = curve.Params().ScalarMult(gx, gy, s)
			}
		}
	})
}
