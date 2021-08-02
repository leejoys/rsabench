package cryptoBench

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

var result []byte

func Benchmark_RSA2048(b *testing.B) { RSANkeyLong(2048, b) }

func Benchmark_RSA4096(b *testing.B) { RSANkeyLong(4096, b) }

func RSANkeyLong(n int, b *testing.B) {

	senderPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	senderPublicKey := &senderPrivateKey.PublicKey

	receiverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	receiverPublicKey := &receiverPrivateKey.PublicKey

	label := []byte("")
	hash := sha256.New()

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto
	newhash := crypto.SHA256
	pssh := newhash.New()

	NLongString := func(n int, b *testing.B) {
		b.StopTimer()
		for i := 0; i < b.N; i++ {
			message := []byte(generateString(n))
			b.ReportAllocs()
			b.StartTimer()

			ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, receiverPublicKey, message, label)
			if err != nil {
				b.Fatal(err)
			}

			pssh.Write(message)
			hashed := pssh.Sum(nil)
			signature, err := rsa.SignPSS(rand.Reader, senderPrivateKey, newhash, hashed, &opts)
			if err != nil {
				b.Fatal(err)
			}

			message, err = rsa.DecryptOAEP(hash, rand.Reader, receiverPrivateKey, ciphertext, label)
			if err != nil {
				b.Fatal(err)
			}

			err = rsa.VerifyPSS(senderPublicKey, newhash, hashed, signature, &opts)
			if err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			result = message
		}
	}

	b.Run("string47", func(b *testing.B) { NLongString(47, b) })

	b.Run("string94", func(b *testing.B) { NLongString(94, b) })

	b.Run("string188", func(b *testing.B) { NLongString(188, b) })

}

func Benchmark_ECIES256(b *testing.B) { ECIESCurveN(elliptic.P256(), b) }
func Benchmark_ECIES521(b *testing.B) { ECIESCurveN(elliptic.P521(), b) }

func ECIESCurveN(ell elliptic.Curve, b *testing.B) {
	prk, err := getKey(ell)
	if err != nil {
		b.Fatal(err)
	}
	prk2 := ecies.ImportECDSA(prk)
	puk2 := prk2.PublicKey

	NLongString := func(n int, b *testing.B) {
		b.StopTimer()
		for i := 0; i < b.N; i++ {
			data := generateString(n)
			bdata := []byte(calculateHashcode(data))
			b.ReportAllocs()
			b.StartTimer()
			endata, err := ECCEncrypt([]byte(bdata), puk2)
			if err != nil {
				b.Fatal(err)
			}

			dedata, err := ECCDecrypt(endata, *prk2)
			if err != nil {
				b.Fatal(err)
			}
			b.StopTimer()
			result = []byte(hex.EncodeToString(endata))
			result = dedata
		}
	}
	b.Run("string47", func(b *testing.B) { NLongString(47, b) })

	b.Run("string94", func(b *testing.B) { NLongString(94, b) })

	b.Run("string188", func(b *testing.B) { NLongString(188, b) })
}
