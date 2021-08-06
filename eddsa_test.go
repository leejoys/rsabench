package cryptoBench

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/cloudflare/circl/sign/ed25519"
)

func TestED25519Main(t *testing.T) {
	var public ed25519.PubKey
	var private ed25519.PrivKey

	_, _ = io.ReadFull(rand.Reader, private[:])

	message := "Hello"

	msg := []byte(message)

	p := ed25519.Pure{}

	p.KeyGen(&public, &private)

	t.Logf("Private:\t%x\n", private)
	t.Logf("Public:\t\t%x\n", public)

	sig := p.Sign(msg, &public, &private)
	t.Logf("\n\nSignature:\t%x\n", *sig)
	t.Logf("msg:\t%x\n", msg)
	t.Logf("message:\t%s\n", string(message))

	ver := p.Verify(msg, &public, sig)
	t.Logf("\n\nSignature verified:\t%t\n", ver)

}
