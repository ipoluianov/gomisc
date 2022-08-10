package crypt_tools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"

	"github.com/btcsuite/btcutil/base58"
)

func GenerateRSAKey() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

func RSAPrivateKeyToBase64(privateKey *rsa.PrivateKey) (privateKey64 string) {
	if privateKey == nil {
		return
	}
	privateKeyBS := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKey64 = base64.StdEncoding.EncodeToString(privateKeyBS)
	return
}

func RSAPrivateKeyToBase58(privateKey *rsa.PrivateKey) (privateKey58 string) {
	if privateKey == nil {
		return
	}
	privateKeyBS := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKey58 = base58.Encode(privateKeyBS)
	return
}

func RSAPrivateKeyFromBase64(privateKey64 string) (privateKey *rsa.PrivateKey, err error) {
	var privateKeyBS []byte
	privateKeyBS, err = base64.StdEncoding.DecodeString(privateKey64)
	if err != nil {
		return
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBS)
	return
}

func RSAPrivateKeyFromBase58(privateKey58 string) (privateKey *rsa.PrivateKey, err error) {
	var privateKeyBS []byte
	privateKeyBS = base58.Decode(privateKey58)
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBS)
	return
}

func RSAPrivateKeyToHex(privateKey *rsa.PrivateKey) (privateKey64 string) {
	if privateKey == nil {
		return
	}
	privateKeyBS := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKey64 = hex.EncodeToString(privateKeyBS)
	return
}

func RSAPrivateKeyFromHex(privateKey64 string) (privateKey *rsa.PrivateKey, err error) {
	var privateKeyBS []byte
	privateKeyBS, err = hex.DecodeString(privateKey64)
	if err != nil {
		return
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyBS)
	return
}

func RSAPrivateKeyToDer(privateKey *rsa.PrivateKey) (privateKeyDer []byte) {
	if privateKey == nil {
		return
	}
	privateKeyDer = x509.MarshalPKCS1PrivateKey(privateKey)
	return
}

func RSAPrivateKeyFromDer(privateKeyDer []byte) (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = x509.ParsePKCS1PrivateKey(privateKeyDer)
	return
}

func RSAPrivateKeyToPem(privateKey *rsa.PrivateKey) (privateKeyPem string) {
	if privateKey == nil {
		return
	}
	privateKeyBS := x509.MarshalPKCS1PrivateKey(privateKey)
	block := pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyBS,
	}
	privateKeyPem = string(pem.EncodeToMemory(&block))
	return
}

func RSAPrivateKeyFromPem(privateKeyPem string) (privateKey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		return nil, errors.New("no pem data")
	}
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	return
}

func RSAPublicKeyToBase64(publicKey *rsa.PublicKey) (publicKey64 string) {
	if publicKey == nil {
		return
	}
	publicKeyBS := x509.MarshalPKCS1PublicKey(publicKey)
	publicKey64 = base64.StdEncoding.EncodeToString(publicKeyBS)
	return
}

func RSAPublicKeyToBase58(publicKey *rsa.PublicKey) (publicKey58 string) {
	if publicKey == nil {
		return
	}
	publicKeyBS := x509.MarshalPKCS1PublicKey(publicKey)
	publicKey58 = base58.Encode(publicKeyBS)
	return
}

func RSAPublicKeyFromBase64(publicKey64 string) (publicKey *rsa.PublicKey, err error) {
	var publicKeyBS []byte
	publicKeyBS, err = base64.StdEncoding.DecodeString(publicKey64)
	if err != nil {
		return
	}
	publicKey, err = x509.ParsePKCS1PublicKey(publicKeyBS)
	return
}

func RSAPublicKeyFromBase58(publicKey58 string) (publicKey *rsa.PublicKey, err error) {
	var publicKeyBS []byte
	publicKeyBS = base58.Decode(publicKey58)
	publicKey, err = x509.ParsePKCS1PublicKey(publicKeyBS)
	return
}

func RSAPublicKeyToHex(publicKey *rsa.PublicKey) (publicKey64 string) {
	if publicKey == nil {
		return
	}
	publicKeyBS := x509.MarshalPKCS1PublicKey(publicKey)
	publicKey64 = hex.EncodeToString(publicKeyBS)
	return
}

func RSAPublicKeyFromHex(publicKey64 string) (publicKey *rsa.PublicKey, err error) {
	var publicKeyBS []byte
	publicKeyBS, err = hex.DecodeString(publicKey64)
	if err != nil {
		return
	}
	publicKey, err = x509.ParsePKCS1PublicKey(publicKeyBS)
	return
}

func RSAPublicKeyToDer(publicKey *rsa.PublicKey) (publicKeyDer []byte) {
	if publicKey == nil {
		return
	}
	publicKeyDer = x509.MarshalPKCS1PublicKey(publicKey)
	return
}

func RSAPublicKeyFromDer(publicKeyDer []byte) (publicKey *rsa.PublicKey, err error) {
	publicKey, err = x509.ParsePKCS1PublicKey(publicKeyDer)
	return
}

func RSAPublicKeyToPem(publicKey *rsa.PublicKey) (publicKeyPem string) {
	if publicKey == nil {
		return
	}
	publicKeyBS := x509.MarshalPKCS1PublicKey(publicKey)

	block := pem.Block{
		Type:    "PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyBS,
	}
	publicKeyPem = string(pem.EncodeToMemory(&block))
	return
}

func RSAPublicKeyFromPem(publicKeyPem string) (publicKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New("no pem data")
	}
	publicKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	return
}
