package minicert

import (
	"bytes"
	//"crypto/rand"
	"encoding/hex"
	//"golang.org/x/crypto/ed25519"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAttributeMarshalUnmarshal(t *testing.T) {
	// Marshal (infallible)
	attrsGood := []Attribute{
		{Type: 0x01, Value: []byte{0x02, 0x03}},
		{Type: 0x04, Value: []byte{0x05, 0x06}},
	}
	attrValGood, _ := hex.DecodeString("000100020203000400020506")
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

	// Unmarshal (too short for attribute header)
	attrValBad, _ := hex.DecodeString("0000")
	_, err = unmarshalAttributes(attrValBad)
	if err == nil {
		t.Fatalf("Unmarshal should not have succeeded")
	}

	// Unmarshal (too short for attribute value)
	attrValBad, _ = hex.DecodeString("000000FF")
	_, err = unmarshalAttributes(attrValBad)
	if err == nil {
		t.Fatalf("Unmarshal should not have succeeded")
	}
}

func TestHeaderFooterMarshalUnmarshal(t *testing.T) {
	// Header marshal (infallible)
	versionGood := uint16(0xA0A0)
	keyAlgGood := uint16(0xB0B0)
	sigAlgGood := uint16(0xC0C0)
	extraGood := uint16(0xD0D0)
	headerGood, _ := hex.DecodeString("A0A0B0B0C0C0D0D0")
	headerTest := marshalHeader(versionGood, keyAlgGood, sigAlgGood, extraGood)
	if !bytes.Equal(headerGood, headerTest) {
		t.Fatalf("Header marshal [%x] != [%x]", headerGood, headerTest)
	}

	// Header unmarshal (infallible)
	versionTest, keyAlgTest, sigAlgTest, extraTest := unmarshalHeader(headerGood)
	if versionTest != versionGood ||
		keyAlgTest != keyAlgGood ||
		sigAlgTest != sigAlgGood ||
		extraTest != extraGood {
		t.Fatalf("Header unmarshal")
	}

	// Footer marshal (success)
	keyAlg, keyInfo := ECDSA384, algInfo[ECDSA384]
	sigAlg, sigInfo := Ed25519, algInfo[Ed25519]
	notBeforeGood := time.Unix(0x0102030405060708, 0)
	notAfterGood := time.Unix(0x1020304050607080, 0)
	keyGood := bytes.Repeat([]byte{0xA0}, keyInfo.KeySize)
	issuerGood := bytes.Repeat([]byte{0xB0}, sigInfo.IssuerSize)
	sigGood := bytes.Repeat([]byte{0xC0}, sigInfo.SigSize)
	footerGood, _ := hex.DecodeString("01020304050607081020304050607080" +
		hex.EncodeToString(keyGood) +
		hex.EncodeToString(issuerGood) +
		hex.EncodeToString(sigGood))
	footerTest, err := marshalFooter(keyAlg, sigAlg, notBeforeGood, notAfterGood, keyGood, issuerGood, sigGood)
	if err != nil {
		t.Fatalf("Footer marshal failure [%v]", err)
	}
	if !bytes.Equal(footerGood, footerTest) {
		t.Fatalf("Footer marshal [%x] != [%x]", footerGood, footerTest)
	}

	// Footer marshal (unknown key algorithm)
	_, err = marshalFooter(0xFFFF, sigAlg, notBeforeGood, notAfterGood, keyGood, issuerGood, sigGood)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer marshal (unknown sig algorithm)
	_, err = marshalFooter(keyAlg, 0xFFFF, notBeforeGood, notAfterGood, keyGood, issuerGood, sigGood)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer marshal (key wrong size)
	_, err = marshalFooter(keyAlg, sigAlg, notBeforeGood, notAfterGood, nil, issuerGood, sigGood)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer marshal (issuer wrong size)
	_, err = marshalFooter(keyAlg, sigAlg, notBeforeGood, notAfterGood, keyGood, nil, sigGood)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer marshal (key wrong size)
	_, err = marshalFooter(keyAlg, sigAlg, notBeforeGood, notAfterGood, keyGood, issuerGood, nil)
	if err == nil {
		t.Fatalf("Footer marshal should not have succeeded")
	}

	// Footer unmarshal (infallible)
	notBeforeTest, notAfterTest, keyTest, issuerTest, sigTest := unmarshalFooter(keyInfo, sigInfo, footerGood)
	if !notBeforeGood.Equal(notBeforeTest) ||
		!notAfterGood.Equal(notAfterTest) ||
		!bytes.Equal(keyGood, keyTest) ||
		!bytes.Equal(issuerGood, issuerTest) ||
		!bytes.Equal(sigGood, sigTest) {
		t.Fatalf("Footer unmarshal")
	}
}

func TestEEMarshalUnmarshal(t *testing.T) {
	keyAlg, keyInfo := ECDSA384, algInfo[ECDSA384]
	sigAlg, sigInfo := Ed25519, algInfo[Ed25519]

	eeValGood := EndEntityCertificate{
		Version:      0x0000,
		KeyAlgorithm: keyAlg, // 0x0001
		SigAlgorithm: sigAlg, // 0x0010
		Attributes:   []Attribute{{Type: 0x03, Value: []byte{0x04, 0x05}}},
		NotBefore:    time.Unix(0x01, 0),
		NotAfter:     time.Unix(0x02, 0),
		Key:          bytes.Repeat([]byte{0x06}, keyInfo.KeySize),
		Issuer:       bytes.Repeat([]byte{0x07}, sigInfo.KeySize),
		Signature:    bytes.Repeat([]byte{0x08}, sigInfo.SigSize),
	}
	eeGood, _ := hex.DecodeString("0000000100100006" +
		"000300020405" +
		"00000000000000010000000000000002" +
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
	err = eeValBad.Unmarshal(eeGood[:headerSize-1])
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}

	// Unmarshal (unknown key algorithm)
	eeBad, _ := hex.DecodeString("0000FFFF00000000")
	err = eeValBad.Unmarshal(eeBad)
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}

	// Unmarshal (unknown sig algorithm)
	eeBad, _ = hex.DecodeString("00000000FFFF0000")
	err = eeValBad.Unmarshal(eeBad)
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}

	// Unmarshal (wrong certificate size)
	eeBad, _ = hex.DecodeString("00000010001000FF")
	err = eeValBad.Unmarshal(eeBad)
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}

	// Unmarshal (attribute unmarshal failure)
	eeBad, _ = hex.DecodeString("000000100010" + "0004000000FF" + strings.Repeat("A0", 8+8+32+32+64))
	err = eeValBad.Unmarshal(eeBad)
	if err == nil {
		t.Fatalf("EE marshal should not have succeeded")
	}
}

func TestCAMarshalUnmarshal(t *testing.T) {
	keyAlg, keyInfo := ECDSA384, algInfo[ECDSA384]
	sigAlg, sigInfo := Ed25519, algInfo[Ed25519]

	caValGood := AuthorityCertificate{
		Version:      0x0000,
		KeyAlgorithm: keyAlg, // 0x0001
		SigAlgorithm: sigAlg, // 0x0010
		Flags:        0xFEFF,
		NotBefore:    time.Unix(0x01, 0),
		NotAfter:     time.Unix(0x02, 0),
		Key:          bytes.Repeat([]byte{0x06}, keyInfo.KeySize),
		Issuer:       bytes.Repeat([]byte{0x07}, sigInfo.IssuerSize),
		Signature:    bytes.Repeat([]byte{0x08}, sigInfo.SigSize),
	}
	caGood, _ := hex.DecodeString("000000010010FEFF" +
		"00000000000000010000000000000002" +
		hex.EncodeToString(caValGood.Key) +
		hex.EncodeToString(caValGood.Issuer) +
		hex.EncodeToString(caValGood.Signature))

	// Marshal (success)
	caTest, err := caValGood.Marshal()
	if err != nil {
		t.Fatalf("CA marshal failure [%v]", err)
	}
	if !bytes.Equal(caGood, caTest) {
		t.Fatalf("CA marshal [%x] != [%x]", caGood, caTest)
	}

	// Marshal (footer marshal failure)
	caValBad := AuthorityCertificate{}
	_, err = caValBad.Marshal()
	if err == nil {
		t.Fatalf("CA marshal should not have succeeded")
	}

	// Unmarshal (success)
	// TODO: Un-fuck this
	var caValTest AuthorityCertificate
	err = caValTest.Unmarshal(caGood)
	if err != nil {
		t.Fatalf("CA unmarshal failure [%v]", err)
	}
	if !reflect.DeepEqual(caValGood, caValTest) {
		t.Fatalf("CA unmarshal [%+v] != [%+v]", caValGood, caValTest)
	}

	// Unmarshal (too short)
	err = caValBad.Unmarshal(caGood[:headerSize-1])
	if err == nil {
		t.Fatalf("CA unmarshal should not have succeeded")
	}

	// Unmarshal (unknown key algorithm)
	caBad, _ := hex.DecodeString("0000FFFF00000000")
	err = caValBad.Unmarshal(caBad)
	if err == nil {
		t.Fatalf("CA unmarshal should not have succeeded")
	}

	// Unmarshal (unknown sig algorithm)
	caBad, _ = hex.DecodeString("00000000FFFF0000")
	err = caValBad.Unmarshal(caBad)
	if err == nil {
		t.Fatalf("CA unmarshal should not have succeeded")
	}

	// Unmarshal (wrong certificate size)
	caBad, _ = hex.DecodeString("00000010001000FF")
	err = caValBad.Unmarshal(caBad)
	if err == nil {
		t.Fatalf("CA unmarshal should not have succeeded")
	}

	// Unmarshal (attribute unmarshal failure)
	caBad, _ = hex.DecodeString("000000100010" + "0004000000FF" + strings.Repeat("A0", 8+8+32+32+64))
	err = caValBad.Unmarshal(caBad)
	if err == nil {
		t.Fatalf("CA unmarshal should not have succeeded")
	}
}

func TestSignVerify(t *testing.T) {
	alg := Ed25519
	info := algInfo[alg]
	priv, pub := info.GenerateKey()
	//
	//	// End entity
	ee := EndEntityCertificate{
		Version:      0x00,
		KeyAlgorithm: alg,
		Attributes:   []Attribute{{Type: 0x03, Value: []byte{0x04, 0x05}}},
		NotBefore:    time.Unix(0x01, 0),
		NotAfter:     time.Unix(0x02, 0),
		Key:          pub,
	}
	eeBadAlg := EndEntityCertificate{SigAlgorithm: 0xFFFF}
	eeBadForm := EndEntityCertificate{SigAlgorithm: alg}
	eeBadSig := EndEntityCertificate{
		KeyAlgorithm: alg,
		SigAlgorithm: alg,
		Key:          pub,
		Issuer:       pub,
		Signature:    bytes.Repeat([]byte{0x00}, info.SigSize),
	}

	err := ee.Sign(alg, priv)
	if err != nil {
		t.Fatalf("EE sign error [%v]", err)
	}

	err = ee.Sign(0xFFFF, priv)
	if err == nil {
		t.Fatalf("EE sign should not have succeeded")
	}

	err = eeBadForm.Sign(alg, priv)
	if err == nil {
		t.Fatalf("EE sign should not have succeeded")
	}

	err = ee.Verify(pub)
	if err != nil {
		t.Fatalf("EE verify error [%v]", err)
	}

	err = eeBadAlg.Verify(pub)
	if err == nil {
		t.Fatalf("EE verify should not have succeeded")
	}

	err = eeBadForm.Verify(pub)
	if err == nil {
		t.Fatalf("EE verify should not have succeeded")
	}

	err = eeBadSig.Verify(pub)
	if err == nil {
		t.Fatalf("EE verify should not have succeeded")
	}

	// Authority
	ca := AuthorityCertificate{
		Version:      0x0000,
		KeyAlgorithm: alg,
		SigAlgorithm: alg,
		Flags:        0xFEFF,
		NotBefore:    time.Unix(0x01, 0),
		NotAfter:     time.Unix(0x02, 0),
		Key:          pub,
	}
	caBadAlg := AuthorityCertificate{SigAlgorithm: 0xFFFF}
	caBadForm := AuthorityCertificate{SigAlgorithm: alg}
	caBadSig := AuthorityCertificate{
		KeyAlgorithm: alg,
		SigAlgorithm: alg,
		Key:          pub,
		Issuer:       pub,
		Signature:    bytes.Repeat([]byte{0x00}, info.SigSize),
	}

	err = ca.Sign(alg, priv)
	if err != nil {
		t.Fatalf("CA sign error [%v]", err)
	}

	err = ca.Sign(0xFFFF, priv)
	if err == nil {
		t.Fatalf("CA sign should not have succcaded")
	}

	err = caBadForm.Sign(alg, priv)
	if err == nil {
		t.Fatalf("CA sign should not have succcaded")
	}

	err = ca.Verify(pub)
	if err != nil {
		t.Fatalf("CA verify error [%v]", err)
	}

	err = caBadAlg.Verify(pub)
	if err == nil {
		t.Fatalf("CA verify should not have succcaded")
	}

	err = caBadForm.Verify(pub)
	if err == nil {
		t.Fatalf("CA verify should not have succcaded")
	}

	err = caBadSig.Verify(pub)
	if err == nil {
		t.Fatalf("CA verify should not have succcaded")
	}
}

// Cert chains for testing:
// ee <-- 1 <-- 2
// </> <-- 3
func TestParentChild(t *testing.T) {
	_, pubE := algInfo[ECDSA256].GenerateKey()
	priv1, pub1 := algInfo[Ed25519].GenerateKey()
	priv2, pub2 := algInfo[ECDSA384].GenerateKey()
	priv3, pub3 := algInfo[Ed25519].GenerateKey()

	ee := &EndEntityCertificate{KeyAlgorithm: ECDSA256, Key: pubE}
	ca1 := &AuthorityCertificate{KeyAlgorithm: Ed25519, Key: pub1}
	ca2 := &AuthorityCertificate{KeyAlgorithm: ECDSA384, Key: pub2}
	ca3 := &AuthorityCertificate{KeyAlgorithm: Ed25519, Key: pub3}

	ee.Sign(Ed25519, priv1)
	ca1.Sign(ECDSA384, priv2)
	ca2.Sign(ECDSA384, priv2)
	ca3.Sign(Ed25519, priv3)

	pc := issuerEE(ca1, ee)
	if !pc {
		t.Fatalf("Failed to recognize valid EE/CA relationship")
	}

	pc = issuerEE(ca3, ee)
	if pc {
		t.Fatalf("Recognized an invalid CA/CA relationship")
	}

	pc = parentChild(ca2, ca1)
	if !pc {
		t.Fatalf("Failed to recognize valid CA/CA relationship")
	}

	pc = parentChild(ca3, ca1)
	if pc {
		t.Fatalf("Recognized an invalid CA/CA relationship")
	}

	// Test that bad algorithms get rejected
	eeBadAlgo := &EndEntityCertificate{SigAlgorithm: 0xFFFF}
	caBadAlgo := &AuthorityCertificate{SigAlgorithm: 0xFFFF}

	pc = issuerEE(ca1, eeBadAlgo)
	if pc {
		t.Fatalf("Recognized an invalid EE/CA relationship")
	}

	pc = parentChild(ca1, caBadAlgo)
	if pc {
		t.Fatalf("Recognized an invalid CA/CA relationship")
	}

}

// Pool of certificates for testing
//
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
// Expected path building results:
//	 maxPathLen = 3
//	===
//   1=D -> 4 5
//   2=F -> 0 1 2
func TestVerifyChain(t *testing.T) {
	alg := Ed25519
	info := algInfo[alg]
	_, pubX := info.GenerateKey()
	privY, pubY := info.GenerateKey()
	privA, pubA := info.GenerateKey()
	privB, pubB := info.GenerateKey()
	privC, pubC := info.GenerateKey()
	privD, pubD := info.GenerateKey()
	privE, pubE := info.GenerateKey()
	privF, pubF := info.GenerateKey()
	_, pub0 := info.GenerateKey()
	priv1, pub1 := info.GenerateKey()

	ee := &EndEntityCertificate{KeyAlgorithm: alg, Key: pubX}
	ee.Sign(alg, privA)

	ee2 := &EndEntityCertificate{KeyAlgorithm: alg, Key: pubY}
	ee2.Sign(alg, privY)

	auth0 := &AuthorityCertificate{KeyAlgorithm: alg, Key: pubA}
	auth1 := &AuthorityCertificate{KeyAlgorithm: alg, Key: pubB}
	auth2 := &AuthorityCertificate{KeyAlgorithm: alg, Key: pubE}
	auth3 := &AuthorityCertificate{KeyAlgorithm: alg, Key: pubC}
	auth4 := &AuthorityCertificate{KeyAlgorithm: alg, Key: pubA}
	auth5 := &AuthorityCertificate{KeyAlgorithm: alg, Key: pubC}
	auth6 := &AuthorityCertificate{KeyAlgorithm: alg, Key: pub0}

	auth0.Sign(alg, privB)
	auth1.Sign(alg, privE)
	auth2.Sign(alg, privF)
	auth3.Sign(alg, privB)
	auth4.Sign(alg, privC)
	auth5.Sign(alg, privD)
	auth6.Sign(alg, priv1)

	authorities := []*AuthorityCertificate{
		auth0, auth1, auth2, auth3,
		auth4, auth5, auth6,
	}

	// Verify with path building (successful)
	trusted := [][]byte{pubD, pubF, pub1}
	err := Verify(ee, authorities, trusted)
	if err != nil {
		t.Fatalf("Verification with path building test [%v]", err)
	}

	// Verify with path building (no EE issuer)
	err = Verify(ee2, authorities, trusted)
	if err == nil {
		t.Fatalf("Verification with path building should not have succeeded")
	}

	// Verify with path building (no plausible path to trusted)
	err = Verify(ee, authorities, [][]byte{pub1})
	if err == nil {
		t.Fatalf("Verification with path building should not have succeeded")
	}

	// Verify with path building (no valid path)
	// A -0-> B -/1-> E -2-> F
	// |      ^
	// |      3
	// |      |
	// +--4-> C -/5-> D
	authorities[1].Signature = nil
	authorities[5].Signature = nil
	err = Verify(ee, authorities, trusted)
	if err == nil {
		t.Fatalf("Verification with path building should not have succeeded")
	}
	authorities[1].Sign(alg, privE)
	authorities[5].Sign(alg, privD)
}
