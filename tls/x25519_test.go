// Copyright CZ. All rights reserved.
// Author: CZ cz.theng@gmail.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file

package tls

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSharedKey(t *testing.T) {
	var privKey1, privKey2 [32]byte
	rand.Read(privKey1[:])
	rand.Read(privKey2[:])
	x1 := NewX25519()
	x1.ParsePrivateKey(privKey1[:])
	x2 := NewX25519()
	x2.ParsePrivateKey(privKey2[:])

	s1, _ := x1.SharedKey(x2.PublicKey())
	s2, _ := x2.SharedKey(x1.PublicKey())

	if !bytes.Equal(s1, s2) {
		t.Errorf("s1{%v} not equal s2{%v} \n", s1, s2)
	}
}

func TestPublicKey(t *testing.T) {
	prvKey := []byte{0xb8, 0x02, 0x3a, 0xe2, 0xfd, 0xe9, 0xf5, 0x44, 0x06, 0x6b, 0xcf, 0x97, 0x04, 0xcd, 0x01, 0xcd, 0x03, 0xf7, 0x17, 0xb8, 0x98, 0x7f, 0xb4, 0x1a, 0xd2, 0x81, 0x8b, 0x37, 0xe8, 0xed, 0xd9, 0x4f}
	pubKey := []byte{0x79, 0xcb, 0xbe, 0x10, 0xba, 0x87, 0x39, 0xad, 0x19, 0x5c, 0x42, 0x72, 0x1a, 0xfb, 0x57, 0x73, 0x2f, 0x3d, 0x80, 0xbf, 0x7c, 0x0f, 0x0f, 0x79, 0xc1, 0xb3, 0x67, 0x6c, 0xed, 0xa4, 0x5c, 0x00}
	x := NewX25519()
	err := x.ParsePrivateKey(prvKey[:])
	if err != nil {
		t.Fatalf("error %v", err)
	}
	if !bytes.Equal(x.PublicKey(), pubKey) {
		t.Errorf("x1 and x2's public key are the same \n")
	}
}

func TestPEMPublicKey(t *testing.T) {
	prvPemKey := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIADXczyOG8Xa5m1PlK7C2qnOP+omRsDutHXAR0A8Hm95
-----END PRIVATE KEY-----
`
	pubPemKey := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAlkLAk96oLVR5wnMT0XC+ZybQMJA+1KO+UJP6DMFAtg8=
-----END PUBLIC KEY-----
`

	x := NewX25519()
	err := x.ParsePEMPrivateKey(prvPemKey)
	if err != nil {
		t.Fatalf("error %v", err)
	}
	if pubPemKey != x.PEMPublicKey() {
		t.Errorf("pem key not equal \n")
	}

}

func TestParsePEMPublicKey(t *testing.T) {
	pubPemKey := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VuAyEAlkLAk96oLVR5wnMT0XC+ZybQMJA+1KO+UJP6DMFAtg8=
-----END PUBLIC KEY-----
`
	p1, err := parsePEMPublicKey(pubPemKey)
	if err != nil {
		t.Fatalf("p1 parse error \n")
	}
	p2, err := genPEMPublicKey(p1)
	if err != nil {
		t.Fatalf("p2 parse error:%v \n", err)
	}
	if pubPemKey != p2 {
		t.Error("publick key not equal\n")
	}
}

func TestParsePEMPrivateKey(t *testing.T) {
	prvPemKey := `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VuBCIEIADXczyOG8Xa5m1PlK7C2qnOP+omRsDutHXAR0A8Hm95
-----END PRIVATE KEY-----
`
	p1, err := parsePEMPrivateKey(prvPemKey)
	if err != nil {
		t.Fatalf("p1 parse error: %v \n", err)
	}
	p2, err := genPEMPrivateKey(p1)
	if err != nil {
		t.Fatalf("p2 parse error:%v \n", err)
	}
	if len(prvPemKey) != len(p2) {
		t.Errorf("private key not equal %v:%v\n", len(prvPemKey), len(p2))
	}
}
