package minicert

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"time"
)

// TODO: Return built path(s)
// TODO: Check versions
// TODO: Check validity times
// TODO: Define flags to separate EE from CA issuers
// TODO: Factor out path building into a cert pool object

const (
	MinEndEntityCertificateSize = 148
	AuthorityCertificateSize    = 148
)

var (
	headerSize = 8
	endian     = binary.BigEndian
)

// Attribute represents a generic value to
type Attribute struct {
	Type  uint16
	Value []byte
}

func marshalAttributes(attrs []Attribute) []byte {
	attrSize := 0
	for _, attr := range attrs {
		attrSize += 4 + len(attr.Value)
	}

	buf := make([]byte, attrSize)
	start := 0
	for _, attr := range attrs {
		attrLen := len(attr.Value)
		endian.PutUint16(buf[start:start+2], attr.Type)
		endian.PutUint16(buf[start+2:start+4], uint16(attrLen))
		copy(buf[start+4:start+4+attrLen], attr.Value)
		start += 4 + attrLen
	}

	return buf
}

func unmarshalAttributes(data []byte) ([]Attribute, error) {
	start := 0
	end := len(data)
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

func marshalHeader(version, keyAlg, sigAlg, extra uint16) []byte {
	out := make([]byte, headerSize)
	endian.PutUint16(out[:2], version)
	endian.PutUint16(out[2:4], keyAlg)
	endian.PutUint16(out[4:6], sigAlg)
	endian.PutUint16(out[6:], extra)
	return out
}

func unmarshalHeader(data []byte) (version, keyAlg, sigAlg, extra uint16) {
	version = endian.Uint16(data[:2])
	keyAlg = endian.Uint16(data[2:4])
	sigAlg = endian.Uint16(data[4:6])
	extra = endian.Uint16(data[6:8])
	return
}

func marshalFooter(keyAlg, sigAlg uint16, notBefore, notAfter time.Time, key, issuer, sig []byte) ([]byte, error) {
	keyInfo, keyKnown := algInfo[keyAlg]
	sigInfo, sigKnown := algInfo[sigAlg]

	if !keyKnown {
		return nil, fmt.Errorf("minicert: Unknown key algorithm [%d]", keyAlg)
	}

	if !sigKnown {
		return nil, fmt.Errorf("minicert: Unknown signing algorithm [%d]", sigAlg)
	}

	keySize := keyInfo.KeySize
	issuerSize := sigInfo.IssuerSize
	sigSize := sigInfo.SigSize

	if len(key) != keySize {
		return nil, fmt.Errorf("minicert: Incorrect size for key [%d] != [%d]", len(key), keySize)
	}

	if len(issuer) != issuerSize {
		return nil, fmt.Errorf("minicert: Incorrect size for issuer [%d] != [%d]", len(issuer), issuerSize)
	}

	if len(sig) != sigSize {
		return nil, fmt.Errorf("minicert: Incorrect size for signature [%d] != [%d]", len(sig), sigSize)
	}

	out := make([]byte, 8+8+keySize+issuerSize+sigSize)
	endian.PutUint64(out[0:8], uint64(notBefore.Unix()))
	endian.PutUint64(out[8:16], uint64(notAfter.Unix()))
	copy(out[16:16+keySize], key)
	copy(out[16+keySize:16+keySize+issuerSize], issuer)
	copy(out[16+keySize+issuerSize:], sig)
	return out, nil
}

func footerSize(keyInfo, sigInfo algorithmInfo) int {
	return 8 + 8 + keyInfo.KeySize + sigInfo.IssuerSize + sigInfo.SigSize
}

func unmarshalFooter(keyInfo, sigInfo algorithmInfo, data []byte) (notBefore, notAfter time.Time, key, issuer, sig []byte) {
	keySize := keyInfo.KeySize
	issuerSize := sigInfo.IssuerSize
	sigSize := sigInfo.SigSize

	notBefore = time.Unix(int64(endian.Uint64(data[0:8])), 0)
	notAfter = time.Unix(int64(endian.Uint64(data[8:16])), 0)

	key = make([]byte, keySize)
	issuer = make([]byte, issuerSize)
	sig = make([]byte, sigSize)
	copy(key, data[16:16+keySize])
	copy(issuer, data[16+keySize:16+keySize+issuerSize])
	copy(sig, data[16+keySize+issuerSize:])

	return notBefore, notAfter, key, issuer, sig
}

// EndEntityCertificate represents an assertion of a binding of a collection of
// attributes to a public key, with a bounded validity time.
type EndEntityCertificate struct {
	Version      uint16
	KeyAlgorithm uint16
	SigAlgorithm uint16
	Attributes   []Attribute
	NotBefore    time.Time
	NotAfter     time.Time
	Key          []byte
	Issuer       []byte
	Signature    []byte
}

func (cert EndEntityCertificate) Marshal() ([]byte, error) {
	attrs := marshalAttributes(cert.Attributes)
	header := marshalHeader(cert.Version, cert.KeyAlgorithm, cert.SigAlgorithm, uint16(len(attrs)))
	footer, err := marshalFooter(cert.KeyAlgorithm, cert.SigAlgorithm,
		cert.NotBefore, cert.NotAfter,
		cert.Key, cert.Issuer, cert.Signature)
	if err != nil {
		return nil, err
	}

	out := append(header, attrs...)
	return append(out, footer...), nil
}

func (cert *EndEntityCertificate) Unmarshal(data []byte) error {
	if len(data) < headerSize {
		return fmt.Errorf("minicert: Data too short certificate")
	}

	version, keyAlg, sigAlg, attrSize16 := unmarshalHeader(data[:headerSize])
	attrSize := int(attrSize16)
	keyInfo, keyKnown := algInfo[keyAlg]
	sigInfo, sigKnown := algInfo[sigAlg]

	if !keyKnown {
		return fmt.Errorf("minicert: Unknown key algorithm [%d]", keyAlg)
	}

	if !sigKnown {
		return fmt.Errorf("minicert: Unknown signing algorithm [%d]", sigAlg)
	}

	expectedSize := headerSize + attrSize + footerSize(keyInfo, sigInfo)
	if len(data) != expectedSize {
		return fmt.Errorf("minicert: Incorrect certificate size [%d] != [%d]", len(data), expectedSize)
	}

	attrs, err := unmarshalAttributes(data[headerSize : headerSize+attrSize])
	if err != nil {
		return err
	}

	cert.Version, cert.KeyAlgorithm, cert.SigAlgorithm = version, keyAlg, sigAlg
	cert.Attributes = attrs
	cert.NotBefore, cert.NotAfter, cert.Key, cert.Issuer, cert.Signature = unmarshalFooter(keyInfo, sigInfo, data[headerSize+attrSize:])
	return nil
}

func (cert *EndEntityCertificate) Sign(sigAlg uint16, priv []byte) error {
	sigInfo, sigKnown := algInfo[sigAlg]
	if !sigKnown {
		return fmt.Errorf("minicert: Unknown signing algorithm [%d]", sigAlg)
	}

	cert.SigAlgorithm = sigAlg
	cert.Issuer = sigInfo.MakeIssuer(sigInfo.MakePublic(priv))

	cert.Signature = bytes.Repeat([]byte{0}, sigInfo.SigSize)
	tbs, err := cert.Marshal()
	if err != nil {
		return err
	}

	tbs = tbs[:len(tbs)-sigInfo.SigSize]
	cert.Signature = sigInfo.Sign(priv, tbs)
	return nil
}

func (cert EndEntityCertificate) Verify(pub []byte) error {
	sigInfo, sigKnown := algInfo[cert.SigAlgorithm]
	if !sigKnown {
		return fmt.Errorf("minicert: Unknown signing algorithm [%d]", cert.SigAlgorithm)
	}

	tbs, err := cert.Marshal()
	if err != nil {
		return err
	}

	tbs = tbs[:len(tbs)-sigInfo.SigSize]
	if !sigInfo.Verify(pub, tbs, cert.Signature) {
		return fmt.Errorf("minicert: End-entity certificate signature failed to verify")
	}
	return nil
}

// AuthorityCertificate represents a certificate for an intermediate or root
// authority that is allowed to issue other certificates.
type AuthorityCertificate struct {
	Version      uint16
	KeyAlgorithm uint16
	SigAlgorithm uint16
	Flags        uint16
	NotBefore    time.Time
	NotAfter     time.Time
	Key          []byte
	Issuer       []byte
	Signature    []byte
}

func (cert AuthorityCertificate) Marshal() ([]byte, error) {
	header := marshalHeader(cert.Version, cert.KeyAlgorithm, cert.SigAlgorithm, cert.Flags)

	footer, err := marshalFooter(cert.KeyAlgorithm, cert.SigAlgorithm,
		cert.NotBefore, cert.NotAfter,
		cert.Key, cert.Issuer, cert.Signature)
	if err != nil {
		return nil, err
	}

	return append(header, footer...), nil
}

func (cert *AuthorityCertificate) Unmarshal(data []byte) error {
	if len(data) < headerSize {
		return fmt.Errorf("minicert: Data too short certificate")
	}

	version, keyAlg, sigAlg, flags := unmarshalHeader(data[:headerSize])
	keyInfo, keyKnown := algInfo[keyAlg]
	sigInfo, sigKnown := algInfo[sigAlg]

	if !keyKnown {
		return fmt.Errorf("minicert: Unknown key algorithm [%d]", keyAlg)
	}

	if !sigKnown {
		return fmt.Errorf("minicert: Unknown signing algorithm [%d]", sigAlg)
	}

	expectedSize := headerSize + footerSize(keyInfo, sigInfo)
	if len(data) != expectedSize {
		return fmt.Errorf("minicert: Incorrect certificate size [%d] != [%d]", len(data), expectedSize)
	}

	cert.Version, cert.KeyAlgorithm, cert.SigAlgorithm, cert.Flags = version, keyAlg, sigAlg, flags
	cert.NotBefore, cert.NotAfter, cert.Key, cert.Issuer, cert.Signature = unmarshalFooter(keyInfo, sigInfo, data[headerSize:])
	return nil
}

func (cert *AuthorityCertificate) Sign(sigAlg uint16, priv ed25519.PrivateKey) error {
	sigInfo, sigKnown := algInfo[sigAlg]
	if !sigKnown {
		return fmt.Errorf("minicert: Unknown signing algorithm [%d]", sigAlg)
	}

	cert.SigAlgorithm = sigAlg
	cert.Issuer = sigInfo.MakeIssuer(sigInfo.MakePublic(priv))

	cert.Signature = bytes.Repeat([]byte{0}, sigInfo.SigSize)
	tbs, err := cert.Marshal()
	if err != nil {
		return err
	}

	tbs = tbs[:len(tbs)-sigInfo.SigSize]
	cert.Signature = sigInfo.Sign(priv, tbs)
	return nil
}

func (cert AuthorityCertificate) Verify(pub []byte) error {
	sigInfo, sigKnown := algInfo[cert.SigAlgorithm]
	if !sigKnown {
		return fmt.Errorf("minicert: Unknown signing algorithm [%d]", cert.SigAlgorithm)
	}

	tbs, err := cert.Marshal()
	if err != nil {
		return err
	}

	tbs = tbs[:len(tbs)-sigInfo.SigSize]
	if !sigInfo.Verify(pub, tbs, cert.Signature) {
		return fmt.Errorf("minicert: Authority certificate signature failed to verify")
	}
	return nil
}

func issuerEE(auth *AuthorityCertificate, ee *EndEntityCertificate) bool {
	sigInfo, sigKnown := algInfo[ee.SigAlgorithm]
	if !sigKnown {
		return false
	}

	return auth.KeyAlgorithm == ee.SigAlgorithm &&
		sigInfo.IssuerMatch(ee.Issuer, auth.Key) &&
		(ee.Verify(auth.Key) == nil)
}

func parentChild(parent, child *AuthorityCertificate) bool {
	sigInfo, sigKnown := algInfo[child.SigAlgorithm]
	if !sigKnown {
		return false
	}

	return parent.KeyAlgorithm == child.SigAlgorithm &&
		sigInfo.IssuerMatch(child.Issuer, parent.Key) &&
		(child.Verify(parent.Key) == nil)
}

func findPaths(ee *EndEntityCertificate, authorities []*AuthorityCertificate, trusted [][]byte) (map[int][]int, int) {
	nIssuers := 0
	paths := map[int][]int{}
	for i, auth := range authorities {
		if issuerEE(auth, ee) {
			nIssuers += 1
			paths[i] = []int{i}
		} else {
			paths[i] = nil
		}
	}
	if nIssuers == 0 {
		return nil, 0
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
				if parentChild(parent, child) &&
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
			if len(path) < 1 {
				continue
			}

			terminal := authorities[path[len(path)-1]]
			if terminal.Verify(key) == nil {
				keyPaths[i] = path

				if len(path) > maxPathLen {
					maxPathLen = len(path)
				}
			}
		}
	}

	return keyPaths, maxPathLen
}

// Verify finds the shortest path from the provided end-entity certificate to a
// trusted public key, using the pool of authorities provided.
func Verify(ee *EndEntityCertificate, authorities []*AuthorityCertificate, trusted [][]byte) error {
	// Build shortest-path tree from EE => distance for each root
	_, maxPathLen := findPaths(ee, authorities, trusted)
	if maxPathLen == 0 {
		return fmt.Errorf("minicert: No path found")
	}

	return nil
}
