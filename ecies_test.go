package cryptoBench

import (
	"crypto/elliptic"
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/crypto/ecies"
)

func TestEciesMain(t *testing.T) {
	var mt = "20181111"
	var pn = "18811881188"
	var ln = "001"
	var mn = "importantmeeting"
	var rn = "216"
	data := mt + pn + ln + mn + rn
	hdata := calculateHashcode(data)
	t.Log("string:", data)
	t.Log("sha256 encrypted:", hdata)
	bdata := []byte(hdata)
	prk, err := getKey(elliptic.P256())
	if err != nil {
		t.Fatal(err)
	}
	prk2 := ecies.ImportECDSA(prk)
	puk2 := prk2.PublicKey
	endata, err := ECCEncrypt([]byte(bdata), puk2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("ecc public key encrypted:", hex.EncodeToString(endata))
	dedata, err := ECCDecrypt(endata, *prk2)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Private Key Decryption:", string(dedata))
}
