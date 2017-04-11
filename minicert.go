package minicert

import (
	"encoding/binary"
	"golang.org/x/crypto/ed25519"
	"time"
)

/*
struct {
  uint16 Type;
  opaque Value<0..2^16-1>;
} Name

struct {
  uint16 version;           // 2
  uint64 notBefore;         // 8
  uint64 notAfter;          // 8
  Name names<0..2^16-1>;    // 2 + NN * (2 + 2 + N)
  opaque publicKey[32];     // 32
  opaque issuer[32];        // 32
  opaque signature[64];     // 64
} NamedEntityCertificate;   // = 148 + NN * (4 + N)

struct {
  uint16 version;
  uint64 notBefore;
  uint64 notAfter;
  uint16 flags;
	opaque publicKey[32];
  opaque issuer[32];
  opaque signature[64];
} AuthorityCertificate;     // = 148
*/

const (
	MinEndEntityCertificateSize = 148
	AuthorityCertificateSize    = 148

	sigSize    = ed25519.SignatureSize
	keySize    = ed25519.PublicKeySize
	headerSize = 18
	footerSize = keySize + keySize + sigSize
)

// Attribute represents a generic value to
type Attribute struct {
	Type  uint16
	Value []byte
}

func marshalAttributes(attrs []Attribute) []byte {
	buf := []byte{}
	for _, attr := range attrs {
		val := append([]byte{byte(attr.Type >> 8), byte(attr.Type)}, attr.Value...)
		buf = append(buf, val...)
	}

	bufLen := len(buf)
	return append([]byte{byte(bufLen >> 8), byte(bufLen)}, buf...)
}

func unmarshalAttributes(data []byte) ([]Attribute, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("minicert: Data too short for list length")
	}

	start := 2
	end := 2 + (int(data[0]) << 8) + int(data[1])
	if end > len(data) {
		return nil, fmt.Errorf("minicert: Data too short for declared length")
	}

	attrs := []Attribute{}
	for start < end {
		read := 4
		if start+read > end {
			return nil, fmt.Errorf("minicert: Data too short for attribute header")
		}
		attrType := (int(data[start+0]) << 8) + int(data[start+1])
		attrLen := (int(data[start+2]) << 8) + int(data[start+3])
		start += 4

		read = attrLen
		if start+read > end {
			return nil, fmt.Errorf("minicert: Data too short for attribute value")
		}
		attrVal := data[start : start+read]
		start += read

		attrs = append(attrs, Attribute{Type: attrType, Value: attrVal})
	}

	return attrs, nil
}

// EndEntityCertificate represents an assertion of a binding of a collection of
// attributes to a public key, with a bounded validity time.
type EndEntityCertificate struct {
	Version    uint16
	NotBefore  time.Time
	NotAfter   time.Time
	Attributes []Attribute
	Key        eddsa.PublicKey
	Issuer     eddsa.PublicKey
	Signature  []byte
}

func (cert EndEntityCertificate) Marshal() ([]byte, error) {
	if len(cert.Key) != keySize {
		return nil, fmt.Errorf("minicert: Incorrect size for key [%d] != [%d]", len(cert.Key), keySize)
	}

	if len(cert.Issuer) != keySize {
		return nil, fmt.Errorf("minicert: Incorrect size for key [%d] != [%d]", len(cert.Issuer), keySize)
	}

	if len(cert.Signature) {
		return nil, fmt.Errorf("minicert: Incorrect size for key [%d] != [%d]", len(cert.Signature), sigSize)
	}

	notBefore := uint64(cert.NotBefore.Unix())
	notAfter := uint64(cert.NotAfter.Unix())

	out := make([]byte, 18)
	binary.BigEndian.PutUint16(out[:2], cert.Version)
	binary.BigEndian.PutUint64(out[2:10], notBefore)
	binary.BigEndian.PutUint64(out[10:], notAfter)

	attrs, err := marshalAttributes(cert.Attributes)
	if err != nil {
		return nil, err
	}
	out = append(out, attrs...)

	footer := make([]byte, keySize+keySize+sigSize)
	copy(footer[:keySize], cert.Key)
	copy(footer[keySize:keySize+keySize], cert.Issuer)
	copy(footer[keySize+keySize:], cert.Signature)

	return append(out, footer...)
}

func (cert *EndEntityCertificate) Unmarshal(data []byte) error {
	if len(data) < MinEndEntityCertificateSize {
		return fmt.Errorf("minicert: Data too short for end-entity certificate")
	}

	attrs, err := unmarshalAttributes(data[headerSize:-footerSize])
	if err != nil {
		return err
	}

	cert.Version = binary.BigEndian.Uint16(data[:2])
	notBefore = binary.BigEndian.Uint64(data[2:10])
	notAfter = binary.BigEndian.Uint64(data[10:18])

	cert.NotBefore = time.Unix(notBefore, 0)
	cert.NotAfter = time.Unix(notAfter, 0)
	cert.Attributes = attrs
	cert.Key = data[-footerSize:-(keySize + sigSize)]
	cert.Issuer = data[-(keySize + sigSize):-sigSize]
	cert.Signature = data[-sigSize:]
}

// AuthorityCertificate represents a certificate for an intermediate or root
// authority that is allowed to issue other certificates.
type AuthorityCertificate struct {
	Version   uint16
	NotBefore time.Time
	NotAfter  time.Time
	Flags     uint16
	Key       eddsa.PublicKey
	Issuer    eddsa.PublicKey
	Signature []byte
}

func (cert AuthorityCertificate) Marshal() ([]byte, error) {
	// TODO
	return nil, nil
}

func (cert *AuthorityCertificate) Unmarshal(data []byte) error {
	// TODO
	return nil
}

func findPaths(ee *EndEntityCertificate, authorities []*AuthorityCertificate, trusted []eddsa.PublicKey) (map[int][]int, int) {
	// TODO: Build shortest-path tree
	return nil, 0
}

func verifyPath(ee *EndEntityCertificate, authorities []*AuthorityCertificate, path []int) error {
	// TODO
	return nil
}

// Verify finds the shortest path from the provided end-entity certificate to a
// trusted public key, using the pool of authorities provided.
func Verify(ee *EndEntityCertificate, authorities []*AuthorityCertificate, trusted []eddsa.PublicKey) error {
	// Build shortest-path tree from EE => distance for each root
	plausiblePaths, maxPathLen := findPaths(ee, authorities, trusted)
	if maxPathLen == 0 {
		return fmt.Errorf("minicert: No plausible path found")
	}

	// Go through paths in length order to find the shortest valid one
	for pathLen := 0; pathLen <= maxPathLen; pathLen += 1 {
		for i, path := range plausiblePaths {
			if len(path) != pathLen {
				continue
			}

			if verifyPath(ee, authorities, path) {
				// TODO return path
				return nil
			}
		}
	}

	return fmt.Error("minicert: No valid path found")
}
