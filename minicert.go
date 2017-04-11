package minicert

import (
	"bytes"
	"encoding/binary"
	"fmt"
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
		attrType := (uint16(data[start+0]) << 8) + uint16(data[start+1])
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

func marshalHeader(version uint16, notBefore, notAfter time.Time) []byte {
	out := make([]byte, headerSize)
	binary.BigEndian.PutUint16(out[:2], version)
	binary.BigEndian.PutUint64(out[2:10], uint64(notBefore.Unix()))
	binary.BigEndian.PutUint64(out[10:], uint64(notAfter.Unix()))
	return out
}

func unmarshalHeader(data []byte) (uint16, time.Time, time.Time) {
	version := binary.BigEndian.Uint16(data[:2])
	notBefore := int64(binary.BigEndian.Uint64(data[2:10]))
	notAfter := int64(binary.BigEndian.Uint64(data[10:]))
	return version, time.Unix(notBefore, 0), time.Unix(notAfter, 0)
}

func marshalFooter(key, issuer ed25519.PublicKey, sig []byte) ([]byte, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("minicert: Incorrect size for key [%d] != [%d]", len(key), keySize)
	}

	if len(issuer) != keySize {
		return nil, fmt.Errorf("minicert: Incorrect size for issuer [%d] != [%d]", len(issuer), keySize)
	}

	if len(sig) != sigSize {
		return nil, fmt.Errorf("minicert: Incorrect size for signature [%d] != [%d]", len(sig), sigSize)
	}

	out := make([]byte, keySize+keySize+sigSize)
	copy(out[:keySize], key)
	copy(out[keySize:keySize+keySize], issuer)
	copy(out[keySize+keySize:], sig)
	return out, nil
}

func unmarshalFooter(data []byte) (ed25519.PublicKey, ed25519.PublicKey, []byte) {
	key := make([]byte, keySize)
	issuer := make([]byte, keySize)
	sig := make([]byte, sigSize)

	copy(key, data[:keySize])
	copy(issuer, data[keySize:2*keySize])
	copy(sig, data[2*keySize:])
	return key, issuer, sig
}

// EndEntityCertificate represents an assertion of a binding of a collection of
// attributes to a public key, with a bounded validity time.
type EndEntityCertificate struct {
	Version    uint16
	NotBefore  time.Time
	NotAfter   time.Time
	Attributes []Attribute
	Key        ed25519.PublicKey
	Issuer     ed25519.PublicKey
	Signature  []byte
}

func (cert EndEntityCertificate) Marshal() ([]byte, error) {
	header := marshalHeader(cert.Version, cert.NotBefore, cert.NotAfter)
	attrs := marshalAttributes(cert.Attributes)
	footer, err := marshalFooter(cert.Key, cert.Issuer, cert.Signature)
	if err != nil {
		return nil, err
	}

	out := append(header, attrs...)
	return append(out, footer...), nil
}

func (cert *EndEntityCertificate) Unmarshal(data []byte) error {
	if len(data) < MinEndEntityCertificateSize {
		return fmt.Errorf("minicert: Data too short for end-entity certificate")
	}

	attrs, err := unmarshalAttributes(data[headerSize : len(data)-footerSize])
	if err != nil {
		return err
	}

	cert.Version, cert.NotBefore, cert.NotAfter = unmarshalHeader(data[:headerSize])
	cert.Attributes = attrs
	cert.Key, cert.Issuer, cert.Signature = unmarshalFooter(data[len(data)-footerSize:])
	return nil
}

func (cert EndEntityCertificate) Verify() error {
	tbs, err := cert.Marshal()
	if err != nil {
		return err
	}

	tbs = tbs[:len(tbs)-sigSize]
	if !ed25519.Verify(cert.Issuer, tbs, cert.Signature) {
		return fmt.Errorf("minicert: End-entity certificate signature failed to verify")
	}
	return nil
}

// AuthorityCertificate represents a certificate for an intermediate or root
// authority that is allowed to issue other certificates.
type AuthorityCertificate struct {
	Version   uint16
	NotBefore time.Time
	NotAfter  time.Time
	Flags     uint16
	Key       ed25519.PublicKey
	Issuer    ed25519.PublicKey
	Signature []byte
}

func (cert AuthorityCertificate) Marshal() ([]byte, error) {
	header := marshalHeader(cert.Version, cert.NotBefore, cert.NotAfter)

	footer, err := marshalFooter(cert.Key, cert.Issuer, cert.Signature)
	if err != nil {
		return nil, err
	}

	flags := make([]byte, 2)
	binary.BigEndian.PutUint16(flags, cert.Flags)

	out := append(header, flags...)
	return append(out, footer...), nil
}

func (cert *AuthorityCertificate) Unmarshal(data []byte) error {
	if len(data) != AuthorityCertificateSize {
		return fmt.Errorf("minicert: Data too short for authority certificate")
	}

	cert.Version, cert.NotBefore, cert.NotAfter = unmarshalHeader(data[:headerSize])
	cert.Flags = binary.BigEndian.Uint16(data[headerSize : headerSize+2])
	cert.Key, cert.Issuer, cert.Signature = unmarshalFooter(data[len(data)-footerSize:])
	return nil
}

func (cert AuthorityCertificate) Verify() error {
	tbs, err := cert.Marshal()
	if err != nil {
		return err
	}

	tbs = tbs[:len(tbs)-sigSize]
	if !ed25519.Verify(cert.Issuer, tbs, cert.Signature) {
		return fmt.Errorf("minicert: Authority certificate signature failed to verify")
	}
	return nil
}

func findPaths(ee *EndEntityCertificate, authorities []*AuthorityCertificate, trusted []ed25519.PublicKey) (map[int][]int, int) {
	paths := map[int][]int{}
	for i, auth := range authorities {
		if bytes.Equal(ee.Issuer, auth.Key) {
			paths[i] = []int{i}
		} else {
			paths[i] = nil
		}
	}

	// Build a shortest-path tree over the authorities
	for {
		loops := 0
		changed := 0

		for i, child := range authorities {
			if paths[i] == nil {
				continue
			}

			for j, parent := range authorities {
				if bytes.Equal(child.Issuer, parent.Key) &&
					(paths[j] == nil || len(paths[j]) > len(paths[i])+1) {
					paths[j] = append(paths[i], j)
					changed += 1
				}
			}
		}

		loops += 1
		if changed == 0 || loops > len(authorities) {
			break
		}
	}

	// Filter to paths that end in trusted keys
	keyPaths := map[int][]int{}
	maxPathLen := 0
	for i, key := range trusted {
		for _, path := range paths {
			terminal := authorities[path[len(path)-1]]
			if bytes.Equal(terminal.Issuer, key) {
				keyPaths[i] = path

				if len(path) > maxPathLen {
					maxPathLen = len(path)
				}
			}
		}
	}

	return keyPaths, maxPathLen
}

func verifyPath(ee *EndEntityCertificate, authorities []*AuthorityCertificate, path []int) error {
	err := ee.Verify()
	if len(path) == 0 || err != nil {
		return err
	}

	// TODO: Check flags in issuer
	if !bytes.Equal(ee.Issuer, authorities[path[0]].Key) {
		return fmt.Errorf("minicert: First authority does not verify end entity")
	}

	curr := authorities[path[0]]
	next := authorities[path[1]]
	for i := 1; i < len(path); i += 1 {
		if err = curr.Verify(); err != nil {
			return err
		}

		// TODO: Check flags in issuer
		if !bytes.Equal(curr.Issuer, next.Key) {
			return fmt.Errorf("minicert: Path step invalid [%d:%d] -> [%d:%d]", i-1, path[i-1], i, path[i])
		}

		curr = next
		next = authorities[path[i]]
	}

	return nil
}

// Verify finds the shortest path from the provided end-entity certificate to a
// trusted public key, using the pool of authorities provided.
func Verify(ee *EndEntityCertificate, authorities []*AuthorityCertificate, trusted []ed25519.PublicKey) error {
	// Build shortest-path tree from EE => distance for each root
	plausiblePaths, maxPathLen := findPaths(ee, authorities, trusted)
	if maxPathLen == 0 {
		return fmt.Errorf("minicert: No plausible path found")
	}

	// Go through paths in length order to find the shortest valid one
	for pathLen := 0; pathLen <= maxPathLen; pathLen += 1 {
		for _, path := range plausiblePaths {
			if len(path) != pathLen {
				continue
			}

			if verifyPath(ee, authorities, path) == nil {
				// TODO return path
				return nil
			}
		}
	}

	return fmt.Errorf("minicert: No valid path found")
}
