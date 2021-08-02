package cryptoBench

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

var result []byte

func Benchmark_RSA2048_47(b *testing.B) { RSA(2048, []byte(generateString(47)), b) }

func Benchmark_RSA2048_94(b *testing.B) { RSA(2048, []byte(generateString(94)), b) }

func Benchmark_RSA2048_188(b *testing.B) { RSA(2048, []byte(generateString(188)), b) }

func Benchmark_RSA4096_47(b *testing.B) { RSA(4096, []byte(generateString(47)), b) }

func Benchmark_RSA4096_94(b *testing.B) { RSA(4096, []byte(generateString(94)), b) }

func Benchmark_RSA4096_188(b *testing.B) { RSA(4096, []byte(generateString(188)), b) }

func Benchmark_RSA2048Encrypt(b *testing.B) { RSAEncrypt(2048, []byte(generateString(188)), b) }

func Benchmark_RSA4096Encrypt(b *testing.B) { RSAEncrypt(4096, []byte(generateString(188)), b) }

func Benchmark_RSA2048Decrypt(b *testing.B) { RSADecrypt(2048, []byte(generateString(188)), b) }

func Benchmark_RSA4096Decrypt(b *testing.B) { RSADecrypt(4096, []byte(generateString(188)), b) }

func RSA(key int, message []byte, b *testing.B) {
	b.StopTimer()
	senderPrivateKey, err := rsa.GenerateKey(rand.Reader, key)
	if err != nil {
		b.Fatal(err)
	}
	senderPublicKey := &senderPrivateKey.PublicKey

	receiverPrivateKey, err := rsa.GenerateKey(rand.Reader, key)
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

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
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

func RSAEncrypt(key int, message []byte, b *testing.B) {
	b.StopTimer()
	senderPrivateKey, err := rsa.GenerateKey(rand.Reader, key)
	if err != nil {
		b.Fatal(err)
	}
	_ = &senderPrivateKey.PublicKey

	receiverPrivateKey, err := rsa.GenerateKey(rand.Reader, key)
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

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
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

		b.StopTimer()
		result = ciphertext
		result = signature
	}
}

func RSADecrypt(key int, message []byte, b *testing.B) {
	b.StopTimer()
	senderPrivateKey, err := rsa.GenerateKey(rand.Reader, key)
	if err != nil {
		b.Fatal(err)
	}
	senderPublicKey := &senderPrivateKey.PublicKey

	receiverPrivateKey, err := rsa.GenerateKey(rand.Reader, key)
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

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {

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
		b.StartTimer()
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

// func Benchmark_ECIES256(b *testing.B) { ECIESCurveN(elliptic.P256(), b) }

// func Benchmark_ECIES521(b *testing.B) { ECIESCurveN(elliptic.P521(), b) }

// func ECIESCurveN(ell elliptic.Curve, b *testing.B) {
// 	prk, err := getKey(ell)
// 	if err != nil {
// 		b.Fatal(err)
// 	}
// 	prk2 := ecies.ImportECDSA(prk)
// 	puk2 := prk2.PublicKey

// 	NLongString := func(n int, b *testing.B) {
// 		b.StopTimer()
// 		for i := 0; i < b.N; i++ {
// 			bdata := []byte(generateString(n))
// 			//bdata := []byte(calculateHashcode(data))
// 			b.ReportAllocs()
// 			b.StartTimer()
// 			endata, err := ECCEncrypt([]byte(bdata), puk2)
// 			if err != nil {
// 				b.Fatal(err)
// 			}

// 			dedata, err := ECCDecrypt(endata, *prk2)
// 			if err != nil {
// 				b.Fatal(err)
// 			}
// 			b.StopTimer()
// 			result = []byte(hex.EncodeToString(endata))
// 			result = dedata
// 		}
// 	}
// 	b.Run("string47", func(b *testing.B) { NLongString(47, b) })

// 	b.Run("string94", func(b *testing.B) { NLongString(94, b) })

// 	b.Run("string188", func(b *testing.B) { NLongString(188, b) })
// }
