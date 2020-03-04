// Copyright CZ. All rights reserved.
// Author: CZ cz.theng@gmail.com
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file

package tls

import (
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// X25519 is curve25519 storage item
type X25519 struct {
	privateKey    [32]byte
	publicKey     [32]byte
	privatePEMKey string
	publicPEMKey  string
}

// NewX25519 create a curve25519
func NewX25519() *X25519 {
	x := &X25519{}
	return x
}

// ParsePrivateKey parse private form a byte array
func (x *X25519) ParsePrivateKey(privateKey []byte) error {
	if len(privateKey) != 32 {
		return errors.New("parse private key's lenght is not 32")
	}
	copy(x.privateKey[:], privateKey)
	curve25519.ScalarBaseMult(&x.publicKey, &x.privateKey)
	privatePEMKey, err := genPEMPrivateKey(x.privateKey[:])
	if err != nil {
		return err
	}
	x.privatePEMKey = privatePEMKey
	publicPEMKey, err := genPEMPublicKey(x.publicKey[:])
	if err != nil {
		return err
	}
	x.publicPEMKey = publicPEMKey
	return nil
}

// ParseRandomPrivateKey user an random .
// which from  /dev/urandom on Unix-like system
func (x *X25519) ParseRandomPrivateKey() error {
	var rk [32]byte
	rand.Read(rk[:])
	return x.ParsePrivateKey(rk[:])
}

// ParsePEMPrivateKey parse  a private key from string
func (x *X25519) ParsePEMPrivateKey(privatePEMKey string) error {
	prvKey, err := parsePEMPrivateKey(privatePEMKey)
	if err != nil {
		return err
	}
	err = x.ParsePrivateKey(prvKey)
	if err != nil {
		return err
	}
	return nil
}

// PublicKey return a byte array public key
func (x *X25519) PublicKey() []byte {
	return x.publicKey[:]
}

// PEMPublicKey return  a string public key
func (x *X25519) PEMPublicKey() string {
	return x.publicPEMKey
}

// SharedKey return sharedkey for the two curve25519
func (x *X25519) SharedKey(peerPublicKey []byte) (sharedKey []byte, err error) {
	if len(peerPublicKey) != 32 {
		return nil, errors.New("peer's public key's lenght is not 32")
	}

	var theirPublicKey [32]byte
	copy(theirPublicKey[:], peerPublicKey)
	sharedKey, err = curve25519.X25519(x.privateKey[:], theirPublicKey[:])
	return
}

// ObjID is a  asn1.ObjectIdentifier place holder
type ObjID struct {
	ObjID asn1.ObjectIdentifier
}

func parsePEMPrivateKey(pemKey string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if nil == block {
		return nil, errors.New("pem.Decode with nil block")
	}

	type keyData struct {
		Version int
		ObjID
		WrappedKey []byte
	}

	data := keyData{}
	_, err := asn1.Unmarshal(block.Bytes, &data)
	if err != nil {
		return nil, err
	}
	var key []byte
	_, err = asn1.Unmarshal(data.WrappedKey, &key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func genPEMPrivateKey(privateKey []byte) (string, error) {
	type keyData struct {
		Version int
		ObjID
		WrappedKey []byte
	}
	data := keyData{}
	key, err := asn1.Marshal(privateKey)
	if err != nil {
		return "", err
	}
	data.ObjID = ObjID{
		ObjID: []int{1, 3, 101, 110},
	}
	data.WrappedKey = key
	data.Version = 0

	buf, err := asn1.Marshal(data)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: buf,
	}
	pembuf := pem.EncodeToMemory(block)
	return string(pembuf), nil
}

func parsePEMPublicKey(pemKey string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemKey))
	if nil == block {
		return nil, errors.New("pem.Decode with nil block")
	}

	type keyData struct {
		ObjID
		Key asn1.BitString
	}

	data := keyData{}
	_, err := asn1.Unmarshal(block.Bytes, &data)
	if err != nil {
		return nil, err
	}
	return data.Key.Bytes, nil
}

func genPEMPublicKey(publicKey []byte) (string, error) {
	type keyData struct {
		ObjID
		Key asn1.BitString
	}
	data := keyData{}
	data.Key.Bytes = publicKey
	data.ObjID = ObjID{
		ObjID: []int{1, 3, 101, 110},
	}
	data.Key.BitLength = 8 * len(publicKey)
	buf, err := asn1.Marshal(data)
	if err != nil {
		return "", err
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: buf,
	}
	pembuf := pem.EncodeToMemory(block)
	return string(pembuf), nil
}
