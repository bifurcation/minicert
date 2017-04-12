package minicert

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"golang.org/x/crypto/ed25519"
	"reflect"
	"testing"
	"time"
)

func TestAttributeMarshalUnmarshal(t *testing.T) {
	// Marshal (infallible)
	attrsGood := []Attribute{
		{Type: 0x01, Value: []byte{0x02, 0x03}},
		{Type: 0x04, Value: []byte{0x05, 0x06}},
	}
	attrValGood, _ := hex.DecodeString("000c000100020203000400020506")
	attrValTest := marshalAttributes(attrsGood)
	if !bytes.Equal(attrValGood, attrValTest) {
		t.Fatalf("Attribute marshal [%x] != [%x]", attrValGood, attrValTest)
	}

	// Unmarshal (successful)
	attrsTest, err := unmarshalAttributes(attrValGood)
	if err != nil {
		t.Fatalf("Attribute marshal failure [%v]", err)
	}
	if !reflect.DeepEqual(attrsGood, attrsTest) {
		t.Fatalf("Value decoded improperly [%+v]", attrsTest)
	}

	// Unmarshal (too short for length)
	attrValBad, _ := hex.DecodeString("00")
	_, err = unmarshalAttributes(attrValBad)
	if err == nil {
		t.Fatalf("Unmarshal should not have succeeded")
	}

	// Unmarshal (too short for declared length)
	attrValBad, _ = hex.DecodeString("00FF")
	_, err = unmarshalAttributes(attrValBad)
	if err == nil {
		t.Fatalf("Unmarshal should not have succeeded")
	}

	// Unmarshal (too short for attribute header)
	attrValBad, _ = hex.DecodeString("00020000")
	_, err = unmarshalAttributes(attrValBad)
	if err == nil {
		t.Fatalf("Unmarshal should not have succeeded")
	}

	// Unmarshal (too short for attribute value)
	attrValBad, _ = hex.DecodeString("0004000000FF")
	_, err = unmarshalAttributes(attrValBad)
	if err == nil {
		t.Fatalf("Unmarshal should not have succeeded")
	}
}

func TestHeaderFooterMarshalUnmarshal(t *testing.T) {
	// Header marshal (infallible)
	versionGood := uint16(0xA0A0)
	notBeforeGood := time.Unix(0x0102030405060708, 0)
	notAfterGood := time.Unix(0x01F2F3F4F5F6F7F8, 0)
	headerGood, _ := hex.DecodeString("A0A0010203040506070801F2F3F4F5F6F7F8")
	headerTest := marshalHeader(versionGood, notBeforeGood, notAfterGood)
	if !bytes.Equal(headerGood, headerTest) {
		t.Fatalf("Header marshal [%x] != [%x]", headerGood, headerTest)
	}

	// Header unmarshal (infallible)
	versionTest, notBeforeTest, notAfterTest := unmarshalHeader(headerGood)
	if versionTest != versionGood ||
		!notBeforeGood.Equal(notBeforeTest) ||
		!notAfterGood.Equal(notAfterTest) {
		t.Fatalf("Header unmarshal")
	}

	// Footer marshal (success)
	keyGood := bytes.Repeat([]byte{0xA0}, keySize)
	issuerGood := bytes.Repeat([]byte{0xB0}, keySize)
	sigGood := bytes.Repeat([]byte{0xC0}, sigSize)
	footerGood, _ := hex.DecodeString(hex.EncodeToString(keyGood) +
		hex.EncodeToString(issuerGood) +
		hex.EncodeToString(sigGood))
	footerTest, err := marshalFooter(keyGood, issuerGood, sigGood)
	if err != nil {
		t.Fatalf("Footer marshal failure [%v]", err)
	}
	if !bytes.Equal(footerGood, footerTest) {
		t.Fatalf("Footer marshal [%x] != [%x]", footerGood, footerTest)
	}

	// Footer marshal (key wrong size)
	_, err = marshalFooter(nil, issuerGood, sigGood)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer marshal (issuer wrong size)
	_, err = marshalFooter(keyGood, nil, sigGood)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer marshal (key wrong size)
	_, err = marshalFooter(keyGood, issuerGood, nil)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer unmarshal (infallible)
	keyTest, issuerTest, sigTest := unmarshalFooter(footerGood)
	if !bytes.Equal(keyGood, keyTest) ||
		!bytes.Equal(issuerGood, issuerTest) ||
		!bytes.Equal(sigGood, sigTest) {
		t.Fatalf("Footer unmarshal")
	}
}

func TestEEMarshalUnmarshal(t *testing.T) {
	eeValGood := EndEntityCertificate{
		Version:    0x00,
		NotBefore:  time.Unix(0x01, 0),
		NotAfter:   time.Unix(0x02, 0),
		Attributes: []Attribute{{Type: 0x03, Value: []byte{0x04, 0x05}}},
		Key:        bytes.Repeat([]byte{0x06}, keySize),
		Issuer:     bytes.Repeat([]byte{0x07}, keySize),
		Signature:  bytes.Repeat([]byte{0x08}, sigSize),
	}
	eeGood, _ := hex.DecodeString("000000000000000000010000000000000002" +
		"0006000300020405" +
		hex.EncodeToString(eeValGood.Key) +
		hex.EncodeToString(eeValGood.Issuer) +
		hex.EncodeToString(eeValGood.Signature))

	// Marshal (success)
	eeTest, err := eeValGood.Marshal()
	if err != nil {
		t.Fatalf("EE marshal failure [%v]", err)
	}
	if !bytes.Equal(eeGood, eeTest) {
		t.Fatalf("EE marshal [%x] != [%x]", eeGood, eeTest)
	}

	// Marshal (footer marshal failure)
	eeValBad := EndEntityCertificate{}
	_, err = eeValBad.Marshal()
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}

	// Unmarshal (success)
	var eeValTest EndEntityCertificate
	err = eeValTest.Unmarshal(eeGood)
	if err != nil {
		t.Fatalf("EE unmarshal failure [%v]", err)
	}
	if !reflect.DeepEqual(eeValGood, eeValTest) {
		t.Fatalf("EE unmarshal [%+v] != [%+v]", eeValGood, eeValTest)
	}

	// Unmarshal (too short)
	err = eeValBad.Unmarshal(eeGood[:MinEndEntityCertificateSize-1])
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}

	// Unmarshal (attribute unmarshal failure)
	err = eeValBad.Unmarshal(eeGood[:150])
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}
}

func TestCAMarshalUnmarshal(t *testing.T) {
	caValGood := AuthorityCertificate{
		Version:   0x0000,
		NotBefore: time.Unix(0x01, 0),
		NotAfter:  time.Unix(0x02, 0),
		Flags:     0xFEFF,
		Key:       bytes.Repeat([]byte{0x06}, keySize),
		Issuer:    bytes.Repeat([]byte{0x07}, keySize),
		Signature: bytes.Repeat([]byte{0x08}, sigSize),
	}
	caGood, _ := hex.DecodeString("000000000000000000010000000000000002FEFF" +
		hex.EncodeToString(caValGood.Key) +
		hex.EncodeToString(caValGood.Issuer) +
		hex.EncodeToString(caValGood.Signature))

	// Marshal (success)
	caTest, err := caValGood.Marshal()
	if err != nil {
		t.Fatalf("ca marshal failure [%v]", err)
	}
	if !bytes.Equal(caGood, caTest) {
		t.Fatalf("ca marshal [%x] != [%x]", caGood, caTest)
	}

	// Marshal (footer marshal failure)
	caValBad := AuthorityCertificate{}
	_, err = caValBad.Marshal()
	if err == nil {
		t.Fatalf("ca marshal should not have succcaded")
	}

	// Unmarshal (success)
	var caValTest AuthorityCertificate
	err = caValTest.Unmarshal(caGood)
	if err != nil {
		t.Fatalf("ca unmarshal failure [%v]", err)
	}
	if !reflect.DeepEqual(caValGood, caValTest) {
		t.Fatalf("ca unmarshal [%+v] != [%+v]", caValGood, caValTest)
	}

	// Unmarshal (too short)
	err = caValBad.Unmarshal(caGood[:AuthorityCertificateSize-1])
	if err == nil {
		t.Fatalf("ca marshal should not have succcaded")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// End entity
	ee := EndEntityCertificate{
		Version:    0x00,
		NotBefore:  time.Unix(0x01, 0),
		NotAfter:   time.Unix(0x02, 0),
		Attributes: []Attribute{{Type: 0x03, Value: []byte{0x04, 0x05}}},
		Key:        pub,
		Issuer:     pub,
	}
	eeBadForm := EndEntityCertificate{}
	eeBadSig := EndEntityCertificate{
		Key:       pub,
		Issuer:    pub,
		Signature: bytes.Repeat([]byte{0x00}, sigSize),
	}

	err := ee.Sign(priv)
	if err != nil {
		t.Fatalf("EE sign error [%v]", err)
	}

	err = eeBadForm.Sign(priv)
	if err == nil {
		t.Fatalf("EE sign should not have succeeded")
	}

	err = ee.Verify()
	if err != nil {
		t.Fatalf("EE verify error [%v]", err)
	}

	err = eeBadForm.Verify()
	if err == nil {
		t.Fatalf("EE verify should not have succeeded")
	}

	err = eeBadSig.Verify()
	if err == nil {
		t.Fatalf("EE verify should not have succeeded")
	}

	// Authority
	ca := AuthorityCertificate{
		Version:   0x0000,
		NotBefore: time.Unix(0x01, 0),
		NotAfter:  time.Unix(0x02, 0),
		Flags:     0xFEFF,
		Key:       pub,
		Issuer:    pub,
	}
	caBadForm := AuthorityCertificate{}
	caBadSig := AuthorityCertificate{
		Key:       pub,
		Issuer:    pub,
		Signature: bytes.Repeat([]byte{0x00}, sigSize),
	}

	err = ca.Sign(priv)
	if err != nil {
		t.Fatalf("CA sign error [%v]", err)
	}

	err = caBadForm.Sign(priv)
	if err == nil {
		t.Fatalf("CA sign should not have succcaded")
	}

	err = ca.Verify()
	if err != nil {
		t.Fatalf("CA verify error [%v]", err)
	}

	err = caBadForm.Verify()
	if err == nil {
		t.Fatalf("CA verify should not have succcaded")
	}

	err = caBadSig.Verify()
	if err == nil {
		t.Fatalf("CA verify should not have succcaded")
	}
}

// EE Issuer:  A
// CA Keys:    B C D E F
// Trusted:    1 D F
// Irrelevant: 0 1
//
// Graph:
//
//
// A -0-> B -1-> E -2-> F
// |      ^
// |      3
// |      |
// +--4-> C -5-> D
//
// 0 -6-> 1
//
// Expected Results:
//	 maxPathLen = 3
//	===
//   1=D -> 4 5
//   2=F -> 0 1 2
//
func TestFindPaths(t *testing.T) {
	ee := &EndEntityCertificate{Issuer: []byte{0x0A}}
	authorities := []*AuthorityCertificate{
		&AuthorityCertificate{Key: []byte{0x0A}, Issuer: []byte{0x0B}},
		&AuthorityCertificate{Key: []byte{0x0B}, Issuer: []byte{0x0E}},
		&AuthorityCertificate{Key: []byte{0x0E}, Issuer: []byte{0x0F}},
		&AuthorityCertificate{Key: []byte{0x0C}, Issuer: []byte{0x0B}},
		&AuthorityCertificate{Key: []byte{0x0A}, Issuer: []byte{0x0C}},
		&AuthorityCertificate{Key: []byte{0x0C}, Issuer: []byte{0x0D}},
		&AuthorityCertificate{Key: []byte{0x00}, Issuer: []byte{0x01}},
	}
	trusted := []ed25519.PublicKey{
		{0x01},
		{0x0D},
		{0x0F},
	}

	pathsGood := map[int][]int{
		1: []int{4, 5},
		2: []int{0, 1, 2},
	}
	maxPathLenGood := 3

	paths, maxPathLen := findPaths(ee, authorities, trusted)
	if !reflect.DeepEqual(paths, pathsGood) {
		t.Fatalf("Path building failed [%+v] != [%+v]", paths, pathsGood)
	}
	if maxPathLen != maxPathLenGood {
		t.Fatalf("Incorrect max path len [%+v] != [%+v]", maxPathLen, maxPathLenGood)
	}

}

func TestVerifyChain(t *testing.T) {
	// TODO
}

func TestVerify(t *testing.T) {
	// TODO
}
