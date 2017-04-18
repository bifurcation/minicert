package minicert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"golang.org/x/crypto/ed25519"
	"hash"
	"math/big"
)

type algorithmInfo struct {
	KeySize     int
	IssuerSize  int
	SigSize     int
	GenerateKey func() (private, public []byte)
	MakePublic  func(priv []byte) []byte
	MakeIssuer  func(key []byte) []byte
	IssuerMatch func(issuer, key []byte) bool
	Sign        func(privateKey, message []byte) []byte
	Verify      func(publicKey, message, signature []byte) bool
}

const (
	ECDSA256 uint16 = 0x0000
	ECDSA384 uint16 = 0x0001
	Ed25519  uint16 = 0x0010
	Ed448    uint16 = 0x0011 // Unimplemented
)

var (
	p256    = elliptic.P256()
	p384    = elliptic.P384()
	s256    = sha256.New
	s384    = sha512.New384
	algInfo = map[uint16]algorithmInfo{
		ECDSA256: {
			KeySize:     64,
			IssuerSize:  32,
			SigSize:     64,
			GenerateKey: func() (priv, pub []byte) { return generateECDSA(p256) },
			MakePublic:  func(priv []byte) []byte { return privToPubECDSA(p256, priv) },
			MakeIssuer:  func(key []byte) []byte { return makeHash(s256, key) },
			IssuerMatch: func(issuer, key []byte) bool { return hashMatch(s256, issuer, key) },
			Sign:        func(priv, msg []byte) []byte { return signECDSA(s256, 32, priv, msg) },
			Verify:      func(pub, msg, sig []byte) bool { return verifyECDSA(p256, s256, 32, pub, msg, sig) },
		},
		ECDSA384: {
			KeySize:     96,
			IssuerSize:  48,
			SigSize:     96,
			GenerateKey: func() (priv, pub []byte) { return generateECDSA(p384) },
			MakePublic:  func(priv []byte) []byte { return privToPubECDSA(p384, priv) },
			MakeIssuer:  func(key []byte) []byte { return makeHash(s384, key) },
			IssuerMatch: func(issuer, key []byte) bool { return hashMatch(s384, issuer, key) },
			Sign:        func(priv, msg []byte) []byte { return signECDSA(s384, 48, priv, msg) },
			Verify:      func(pub, msg, sig []byte) bool { return verifyECDSA(p384, s384, 48, pub, msg, sig) },
		},
		Ed25519: {
			KeySize:     32,
			IssuerSize:  32,
			SigSize:     64,
			GenerateKey: generateEd25519,
			MakePublic:  privToPubEd25519,
			MakeIssuer:  func(x []byte) []byte { return x },
			IssuerMatch: equalMatch,
			Sign:        signEd25519,
			Verify:      verifyEd25519,
		},
	}
)

// XXX: Should handle errors more elegantly
func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// GenerateKey
func generateECDSA(curve elliptic.Curve) (priv, pub []byte) {
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	panicOnError(err)

	priv, err = x509.MarshalECPrivateKey(private)
	panicOnError(err)

	pubKey := private.Public().(*ecdsa.PublicKey)
	pub = elliptic.Marshal(curve, pubKey.X, pubKey.Y)[1:]
	return
}

func generateEd25519() (priv, pub []byte) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	panicOnError(err)
	return
}

// MakePublic
func privToPubECDSA(curve elliptic.Curve, priv []byte) (pub []byte) {
	private, err := x509.ParseECPrivateKey(priv)
	panicOnError(err)
	pubKey := private.Public().(*ecdsa.PublicKey)
	pub = elliptic.Marshal(curve, pubKey.X, pubKey.Y)[1:]
	return
}

func privToPubEd25519(priv []byte) (pub []byte) {
	pub = ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	return
}

// MakeIssuer
func makeHash(h func() hash.Hash, key []byte) []byte {
	digest := h()
	digest.Write(key)
	return digest.Sum(nil)
}

// IssuerMatch
func hashMatch(h func() hash.Hash, issuer, key []byte) bool {
	digest := h()
	digest.Write(key)
	return subtle.ConstantTimeCompare(issuer, digest.Sum(nil)) == 1
}

func equalMatch(issuer, key []byte) bool {
	return bytes.Equal(issuer, key)
}

// Sign
func signECDSA(h func() hash.Hash, intSize int, priv, msg []byte) []byte {
	private, err := x509.ParseECPrivateKey(priv)
	panicOnError(err)

	digest := h()
	digest.Write(msg)

	r, s, err := ecdsa.Sign(rand.Reader, private, digest.Sum(nil))
	panicOnError(err)

	rb := r.Bytes()
	sb := s.Bytes()
	rbOff := intSize - len(rb)
	sbOff := intSize - len(sb)

	sig := make([]byte, 2*intSize)
	copy(sig[rbOff:], rb)
	copy(sig[intSize+sbOff:], sb)
	return sig
}

func signEd25519(priv, msg []byte) []byte {
	return ed25519.Sign(priv, msg)
}

// Verify
func verifyECDSA(curve elliptic.Curve, h func() hash.Hash, intSize int, pub, msg, sig []byte) bool {
	encPub := append([]byte{0x04}, pub...)
	x, y := elliptic.Unmarshal(curve, encPub)
	pubKey := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	digest := h()
	digest.Write(msg)

	r := big.NewInt(0).SetBytes(sig[:intSize])
	s := big.NewInt(0).SetBytes(sig[intSize:])
	return ecdsa.Verify(pubKey, digest.Sum(nil), r, s)
}

func verifyEd25519(pub, msg, sig []byte) bool {
	return ed25519.Verify(pub, msg, sig)
}
