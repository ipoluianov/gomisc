package crypt_tools

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
)

func GenerateRSAKey() (privateKey *rsa.PrivateKey, err error) {
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	return
}

func RSAPrivateKeyToBase64(privateKey *rsa.PrivateKey) (privateKey64 string) {
	privateKeyBS := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKey64 = base64.StdEncoding.EncodeToString(privateKeyBS)
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

func RSAPrivateKeyToHex(privateKey *rsa.PrivateKey) (privateKey64 string) {
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

func RSAPrivateKeyToPem(privateKey *rsa.PrivateKey) (privateKeyPem string) {
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
	publicKeyBS := x509.MarshalPKCS1PublicKey(publicKey)
	publicKey64 = base64.StdEncoding.EncodeToString(publicKeyBS)
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

func RSAPublicKeyToHex(publicKey *rsa.PublicKey) (publicKey64 string) {
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

func RSAPublicKeyToPem(publicKey *rsa.PublicKey) (publicKeyPem string) {
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
