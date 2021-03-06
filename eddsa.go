package cryptoBench

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/ed25519"
)

func ED25519Main() {

	var public ed25519.PubKey
	var private ed25519.PrivKey

	_, _ = io.ReadFull(rand.Reader, private[:])

	message := "Hello"

	msg := []byte(message)

	p := ed25519.Pure{}

	p.KeyGen(&public, &private)

	fmt.Printf("Private:\t%x\n", private)
	fmt.Printf("Public:\t\t%x\n", public)

	sig := p.Sign(msg, &public, &private)
	fmt.Printf("\n\nSignature:\t%x\n", *sig)

	ver := p.Verify(msg, &public, sig)
	fmt.Printf("\n\nSignature verified:\t%t\n", ver)

}
