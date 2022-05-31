package sslcerts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

func readCreatePrivateKey(oname string) (*rsa.PrivateKey, error) {
	key, err := readPrivateKey(oname)
	if errors.Is(err, os.ErrNotExist) {
		key, err = createPrivateKey(oname)
	}
	return key, err
}

func createPrivateKey(oname string) (*rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("error generating private key: %v", err)
	}

	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	keyPem, err := os.Create(oname)
	if err != nil {
		return nil, fmt.Errorf("error creating pem file: %v", err)
	}

	err = pem.Encode(keyPem, keyPemBlock)
	if err != nil {
		return nil, fmt.Errorf("error when encode private pem: %v", err)
	}
	return key, nil
}

func readPrivateKey(name string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	keyPemBlock, _ := pem.Decode(keyBytes)
	key, err := x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error when parsing private key: %v", err)
	}

	return key, nil
}

func createPublicKey(oname string, key *rsa.PrivateKey) (*rsa.PublicKey, error) {
	pkey := &key.PublicKey
	pkeyBytes := x509.MarshalPKCS1PublicKey(pkey)
	pkeyPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkeyBytes,
	}

	pkeyPem, err := os.Create(oname)
	if err != nil {
		return nil, err
	}

	err = pem.Encode(pkeyPem, pkeyPemBlock)
	if err != nil {
		return nil, fmt.Errorf("error when encode private pem: %v", err)
	}
	return pkey, nil
}

func createCertificate(oname string, csr *x509.CertificateRequest, parent *x509.Certificate, key *rsa.PrivateKey, ca bool) error {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, max)
	if err != nil {
		return fmt.Errorf("error generating serial number: %v", err)
	}

	tpl := &x509.Certificate{
		Signature:          csr.Signature,
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKey:          csr.PublicKey,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		SerialNumber:       serialNumber,
		Issuer:             csr.Subject,
		Subject:            csr.Subject,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(1, 0, 0),
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	if ca {
		tpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}

	if parent != nil {
		tpl.Issuer = parent.Subject
	} else {
		parent = tpl
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("error generating certificate: %v", err)
	}

	certPemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	certPem, err := os.Create(oname)
	if err != nil {
		return err
	}
	return pem.Encode(certPem, certPemBlock)
}

func readCertificate(name string) (*x509.Certificate, error) {
	crtBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	crtPemBlock, _ := pem.Decode(crtBytes)
	crt, err := x509.ParseCertificate(crtPemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error when parsing certificate: %v", err)
	}

	return crt, nil
}

func createCertificateRequest(oname string, key *rsa.PrivateKey, subj pkix.Name) error {
	tpl := &x509.CertificateRequest{
		Subject: subj,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, tpl, key)
	if err != nil {
		return fmt.Errorf("error generating certificate signing request: %v", err)
	}

	csrPemBlock := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	}

	csrPem, err := os.Create(oname)
	if err != nil {
		return err
	}
	return pem.Encode(csrPem, csrPemBlock)
}

func readCertificateRequest(name string) (*x509.CertificateRequest, error) {
	csrBytes, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}

	csrPemBlock, _ := pem.Decode(csrBytes)
	csr, err := x509.ParseCertificateRequest(csrPemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error when parsing certificate signing request: %v", err)
	}

	return csr, nil
}
