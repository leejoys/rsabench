package cryptoBench

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
	"golang.org/x/crypto/openpgp/elgamal"
)

var result []byte

func Benchmark_RSA2048_47(b *testing.B) {
	RSA(2048, []byte(generateString(47)), b)
}

func Benchmark_RSA2048_94(b *testing.B) {
	RSA(2048, []byte(generateString(94)), b)
}

func Benchmark_RSA2048_188(b *testing.B) {
	RSA(2048, []byte(generateString(188)), b)
}

func Benchmark_RSA4096_47(b *testing.B) {
	RSA(4096, []byte(generateString(47)), b)
}

func Benchmark_RSA4096_94(b *testing.B) {
	RSA(4096, []byte(generateString(94)), b)
}

func Benchmark_RSA4096_188(b *testing.B) {
	RSA(4096, []byte(generateString(188)), b)
}

func Benchmark_RSA2048Encrypt(b *testing.B) {
	RSAEncrypt(2048, []byte(generateString(188)), b)
}

func Benchmark_RSA4096Encrypt(b *testing.B) {
	RSAEncrypt(4096, []byte(generateString(188)), b)
}

func Benchmark_RSA2048Decrypt(b *testing.B) {
	RSADecrypt(2048, []byte(generateString(188)), b)
}

func Benchmark_RSA4096Decrypt(b *testing.B) {
	RSADecrypt(4096, []byte(generateString(188)), b)
}

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

func Benchmark_ECIES256_47(b *testing.B) {
	ECIES(elliptic.P256(), []byte(generateString(47)), b)
}

func Benchmark_ECIES256_94(b *testing.B) {
	ECIES(elliptic.P256(), []byte(generateString(94)), b)
}

func Benchmark_ECIES256_188(b *testing.B) {
	ECIES(elliptic.P256(), []byte(generateString(188)), b)
}

func Benchmark_ECIES521_47(b *testing.B) {
	ECIES(elliptic.P521(), []byte(generateString(47)), b)
}

func Benchmark_ECIES521_94(b *testing.B) {
	ECIES(elliptic.P521(), []byte(generateString(94)), b)
}

func Benchmark_ECIES521_188(b *testing.B) {
	ECIES(elliptic.P521(), []byte(generateString(188)), b)
}

func Benchmark_ECIES256Encrypt(b *testing.B) {
	ECIESEncrypt(elliptic.P256(), []byte(generateString(188)), b)
}

func Benchmark_ECIES521Encrypt(b *testing.B) {
	ECIESEncrypt(elliptic.P521(), []byte(generateString(188)), b)
}

func Benchmark_ECIES256Decrypt(b *testing.B) {
	ECIESDecrypt(elliptic.P256(), []byte(generateString(188)), b)
}

func Benchmark_ECIES521Decrypt(b *testing.B) {
	ECIESDecrypt(elliptic.P521(), []byte(generateString(188)), b)
}

func ECIES(ell elliptic.Curve, message []byte, b *testing.B) {
	b.StopTimer()
	prk, err := getKey(ell)
	if err != nil {
		b.Fatal(err)
	}
	prk2 := ecies.ImportECDSA(prk)
	puk2 := prk2.PublicKey

	//bdata := message  //без хеширования
	bdata := []byte(calculateHashcode(string(message)))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
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

func ECIESEncrypt(ell elliptic.Curve, message []byte, b *testing.B) {
	b.StopTimer()
	prk, err := getKey(ell)
	if err != nil {
		b.Fatal(err)
	}
	prk2 := ecies.ImportECDSA(prk)
	puk2 := prk2.PublicKey

	//bdata := message  //без хеширования
	bdata := []byte(calculateHashcode(string(message)))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		endata, err := ECCEncrypt([]byte(bdata), puk2)
		if err != nil {
			b.Fatal(err)
		}

		b.StopTimer()
		result = []byte(hex.EncodeToString(endata))

	}
}

func ECIESDecrypt(ell elliptic.Curve, message []byte, b *testing.B) {
	b.StopTimer()
	prk, err := getKey(ell)
	if err != nil {
		b.Fatal(err)
	}
	prk2 := ecies.ImportECDSA(prk)
	puk2 := prk2.PublicKey

	//bdata := message  //без хеширования
	bdata := []byte(calculateHashcode(string(message)))

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {

		endata, err := ECCEncrypt([]byte(bdata), puk2)
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
		dedata, err := ECCDecrypt(endata, *prk2)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		result = []byte(hex.EncodeToString(endata))
		result = dedata

	}
}

func Benchmark_Elgamal512_47(b *testing.B) {
	Elgamal("512", []byte(generateString(25)), b)
}

func Benchmark_Elgamal512_94(b *testing.B) {
	Elgamal("512", []byte(generateString(53)), b) //53 максимум для ключа в 512
}

func Benchmark_Elgamal768_53(b *testing.B) {
	Elgamal("768", []byte(generateString(53)), b) //85 максимум для ключа в 768
}

func Benchmark_Elgamal768_85(b *testing.B) {
	Elgamal("768", []byte(generateString(85)), b) //85 максимум для ключа в 768
}

func Benchmark_Elgamal1024_47(b *testing.B) {
	Elgamal("1024", []byte(generateString(47)), b)
}

func Benchmark_Elgamal1024_94(b *testing.B) {
	Elgamal("1024", []byte(generateString(94)), b)
}

func Benchmark_Elgamal1024_188(b *testing.B) {
	Elgamal("1024", []byte(generateString(188)), b)
}

// func Benchmark_Elgamal512Encrypt(b *testing.B) {
// 	ElgamalEncrypt(2048, []byte(generateString(188)), b)
// }

// func Benchmark_Elgamal4096Encrypt(b *testing.B) {
// 	ElgamalEncrypt("1024", []byte(generateString(188)), b)
// }

// func Benchmark_Elgamal512Decrypt(b *testing.B) {
// 	ElgamalDecrypt(2048, []byte(generateString(188)), b)
// }

// func Benchmark_Elgamal4096Decrypt(b *testing.B) {
// 	ElgamalDecrypt("1024", []byte(generateString(188)), b)
// }

func Elgamal(size string, message []byte, b *testing.B) {
	b.StopTimer()

	x := "40"
	xval, _ := new(big.Int).SetString(x, 10)
	g, p, ok := get_g_p(size)
	if !ok {
		b.Fatal("SetString not ok")
	}

	priv := &elgamal.PrivateKey{
		PublicKey: elgamal.PublicKey{
			G: g,
			P: p,
		},
		X: xval,
	}
	priv.Y = new(big.Int).Exp(priv.G, priv.X, priv.P)
	pub := &priv.PublicKey

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StartTimer()

		c1, c2, err := elgamal.Encrypt(rand.Reader, pub, message)
		if err != nil {
			pLen := (pub.P.BitLen() + 7) / 8
			b.Logf("max len %d-11=%d", pLen, pLen-11)
			b.Fatal(err)
		}
		resultBytesOfMessage, err := elgamal.Decrypt(priv, c1, c2)
		if err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		result = resultBytesOfMessage
	}
}
