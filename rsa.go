package cryptoBench

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"log"
	mrand "math/rand"
	"strings"
	"time"
)

func RsaMain() {
	senderPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	senderPublicKey := &senderPrivateKey.PublicKey

	receiverPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}
	receiverPublicKey := &receiverPrivateKey.PublicKey

	fmt.Println("Private Key : ", senderPrivateKey)
	fmt.Println("Public key ", senderPublicKey)
	fmt.Println("Public key Size ", senderPublicKey.Size())
	fmt.Println("Private Key : ", receiverPrivateKey)
	fmt.Println("Public key ", receiverPublicKey)
	fmt.Println("Public key Size ", receiverPublicKey.Size())

	message := []byte("the code must be like a piece of music")
	label := []byte("")
	hash := sha256.New()

	fmt.Println("hash Size ", hash.Size())

	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, receiverPublicKey, message, label)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("OAEP encrypted [%s] to \n[%x]\n", string(message), ciphertext)

	var opts rsa.PSSOptions
	opts.SaltLength = rsa.PSSSaltLengthAuto // for simple example
	PSSmessage := message
	newhash := crypto.SHA256
	pssh := newhash.New()
	pssh.Write(PSSmessage)
	hashed := pssh.Sum(nil)

	signature, err := rsa.SignPSS(rand.Reader, senderPrivateKey, newhash, hashed, &opts)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("PSS Signature : %x\n", signature)

	plainText, err := rsa.DecryptOAEP(hash, rand.Reader, receiverPrivateKey, ciphertext, label)

	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("OAEP decrypted [%x] to \n[%s]\n", ciphertext, plainText)

	err = rsa.VerifyPSS(senderPublicKey, newhash, hashed, signature, &opts)

	if err != nil {
		log.Fatal("Who are U? Verify Signature failed")
	} else {
		fmt.Println("Verify Signature successful")
	}

}

func generateString(size int) string {
	mrand.Seed(time.Now().Unix())
	charSet := "abcdedfghijklmnopqrstABCDEFGHIJKLMNOP"
	var output strings.Builder

	for i := 0; i < size; i++ {
		random := mrand.Intn(len(charSet))
		randomChar := charSet[random]
		output.WriteString(string(randomChar))
	}

	return output.String()
}
