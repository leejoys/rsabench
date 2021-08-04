package cryptoBench

import (
	"crypto/rand"
	"log"
	"math/big"
	"testing"

	"golang.org/x/crypto/openpgp/elgamal"
)

func TestElgamalMain(t *testing.T) {
	var result string
	size := "512"
	message := "hello world"
	x := "40"
	bytesOfMessage := []byte(message)

	xval, _ := new(big.Int).SetString(x, 10)
	g, p, ok := get_g_p(size)
	if !ok {
		log.Fatal("SetString not ok")
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

	a, b, _ := elgamal.Encrypt(rand.Reader, pub, bytesOfMessage)
	resultBytesOfMessage, err := elgamal.Decrypt(priv, a, b)
	if err != nil {
		log.Fatal(err)
	}
	result = string(resultBytesOfMessage)
	t.Log(result)
}
