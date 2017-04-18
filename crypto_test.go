package minicert

import (
	"bytes"
	"testing"
)

func TestCrypto(t *testing.T) {
	msg := []byte("This is a test message.")

	for alg, info := range algInfo {
		priv, pub := info.GenerateKey()
		alsoPub := info.MakePublic(priv)
		issuer := info.MakeIssuer(pub)
		match := info.IssuerMatch(issuer, pub)
		sig := info.Sign(priv, msg)
		ver := info.Verify(pub, msg, sig)

		if len(pub) != info.KeySize {
			t.Fatalf("(%04x) Incorrect key size [%d] != [%d]", alg, len(pub), info.KeySize)
		}

		if len(issuer) != info.IssuerSize {
			t.Fatalf("(%04x) Incorrect issuer size [%d] != [%d]", alg, len(issuer), info.IssuerSize)
		}

		if len(sig) != info.SigSize {
			t.Fatalf("(%04x) Incorrect signature size [%d] != [%d]", alg, len(sig), info.SigSize)
		}

		if !bytes.Equal(pub, alsoPub) {
			t.Fatalf("(%04x) Incorrect public key conversion [%x] != [%x]", alg, pub, alsoPub)
		}

		if !match {
			t.Fatalf("(%04x) Issuer and key failed to match", alg)
		}

		if !ver {
			t.Fatalf("(%04x) Signature failed to verify", alg)
		}
	}
}
