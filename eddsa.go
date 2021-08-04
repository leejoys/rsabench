package cryptoBench

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/ed25519"
)

func ed25519Main() {

	var public ed25519.PubKey
	var private ed25519.PrivKey

	_, _ = io.ReadFull(rand.Reader, private[:])

	argCount := len(os.Args[1:])

	message := "Hello"

	if argCount > 0 {
		message = string(os.Args[1])
	}

	msg := []byte(message)

	ed25519.KeyGen(&public, &private)

	fmt.Printf("Private:\t%x\n", private)
	fmt.Printf("Public:\t\t%x\n", public)

	sig := ed25519.Sign(msg, &public, &private)
	fmt.Printf("\n\nSignature:\t%x\n", *sig)

	ver := ed25519.Verify(msg, &public, sig)
	fmt.Printf("\n\nSignature verified:\t%t\n", ver)

}
