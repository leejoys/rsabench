package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func Benchmark_RSA(b *testing.B) {

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

	b.Run("2048string47", func(b *testing.B) {
		b.StopTimer()
		for i := 0; i < b.N; i++ {
			message := []byte(generateString(47))
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
			pssh.Write(message) //_
		}
	})

	b.Run("2048string94", func(b *testing.B) {
		b.StopTimer()
		for i := 0; i < b.N; i++ {
			message := []byte(generateString(94))
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
			pssh.Write(message) //_
		}
	})

	b.Run("2048string188", func(b *testing.B) {
		b.StopTimer()
		for i := 0; i < b.N; i++ {
			message := []byte(generateString(188))
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
			pssh.Write(message) //_
		}
	})

}
