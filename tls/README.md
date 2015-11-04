# TLS

golang `crypto/tls` implements TLS 1.2

- client random + server random = pre-master secret
- pre-master secret -> master secret

master secret is used for symmetric key & Message Authentication Code(MAC) key & CBC Initial Vector(IV)


## client

### ClientHello

```golang
var cipherSuites = []*cipherSuite{
    // Ciphersuite order is chosen so that ECDHE comes before plain RSA
    // and RC4 comes before AES (because of the Lucky13 attack).
	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256..}
	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256..}
	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384..}
	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384..}
	{TLS_ECDHE_RSA_WITH_RC4_128_SHA..}
	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA..}
	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA..}
	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA..}
	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA..}
	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA..}
	{TLS_RSA_WITH_RC4_128_SHA..}
	{TLS_RSA_WITH_AES_128_CBC_SHA..}
	{TLS_RSA_WITH_AES_256_CBC_SHA..}
	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA..}
	{TLS_RSA_WITH_3DES_EDE_CBC_SHA..}
}    
```

### Certificate

```golang
func (hs *clientHandshakeState) doFullHandshake() error
```

```golang
msg, err := c.readHandshake()
if err != nil {
    return err
}

certMsg, ok := msg.(*certificateMsg)

certs := make([]*x509.Certificate, len(certMsg.certificates))
for i, asn1Data := range certMsg.certificates {
    cert, err := x509.ParseCertificate(asn1Data)
    if err != nil {
        c.sendAlert(alertBadCertificate)
        return errors.New("tls: failed to parse certificate from server: " + err.Error())
    }
    certs[i] = cert
}

if !c.config.InsecureSkipVerify {
    opts := x509.VerifyOptions{
        Roots:         c.config.RootCAs,
        CurrentTime:   c.config.time(),
        DNSName:       c.config.ServerName,
        Intermediates: x509.NewCertPool(),
    }

    for i, cert := range certs {
        if i == 0 {
            continue
        }
        opts.Intermediates.AddCert(cert)
    }
    c.verifiedChains, err = certs[0].Verify(opts)
    if err != nil {
        c.sendAlert(alertBadCertificate)
        return err
    }
}
```

### preMasterSecret (RSA)

On client side (ecrypt by public key),

```golang
func (ka rsaKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	preMasterSecret := make([]byte, 48)
	preMasterSecret[0] = byte(clientHello.vers >> 8)
	preMasterSecret[1] = byte(clientHello.vers)
	_, err := io.ReadFull(config.rand(), preMasterSecret[2:])
	if err != nil {
		return nil, nil, err
	}

	encrypted, err := rsa.EncryptPKCS1v15(config.rand(), cert.PublicKey.(*rsa.PublicKey), preMasterSecret)
	if err != nil {
		return nil, nil, err
	}
	ckx := new(clientKeyExchangeMsg)
	ckx.ciphertext = make([]byte, len(encrypted)+2)
	ckx.ciphertext[0] = byte(len(encrypted) >> 8)
	ckx.ciphertext[1] = byte(len(encrypted))
	copy(ckx.ciphertext[2:], encrypted)
	return preMasterSecret, ckx, nil
}
```

On server side (decrypt by private key),

```golang
func (ka rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	if len(ckx.ciphertext) < 2 {
		return nil, errClientKeyExchange
	}

	ciphertext := ckx.ciphertext
	if version != VersionSSL30 {
		ciphertextLen := int(ckx.ciphertext[0])<<8 | int(ckx.ciphertext[1])
		if ciphertextLen != len(ckx.ciphertext)-2 {
			return nil, errClientKeyExchange
		}
		ciphertext = ckx.ciphertext[2:]
	}
	priv, ok := cert.PrivateKey.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("tls: certificate private key does not implement crypto.Decrypter")
	}
	// Perform constant time RSA PKCS#1 v1.5 decryption
	preMasterSecret, err := priv.Decrypt(config.rand(), ciphertext, &rsa.PKCS1v15DecryptOptions{SessionKeyLen: 48})
	if err != nil {
		return nil, err
	}

	return preMasterSecret, nil
}
```

### masterSecret


```golang
hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.hello.random, hs.serverHello.ran\
dom)
```

```golang
// masterFromPreMasterSecret generates the master secret from the pre-master
// secret. See http://tools.ietf.org/html/rfc5246#section-8.1
func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte)[]byte {
    var seed [tlsRandomLength * 2]byte
    copy(seed[0:len(clientRandom)], clientRandom)
    copy(seed[len(clientRandom):], serverRandom)
    masterSecret := make([]byte, masterSecretLength)
    prfForVersion(version, suite)(masterSecret, preMasterSecret, masterSecretLabel, seed[0:])
    return masterSecret
}
```

## MAC

```golang
// macSHA1 returns a macFunction for the given protocol version.
func macSHA1(version uint16, key []byte) macFunction {
	if version == VersionSSL30 {
		mac := ssl30MAC{
			h:   sha1.New(),
			key: make([]byte, len(key)),
		}
		copy(mac.key, key)
		return mac
	}
	return tls10MAC{hmac.New(sha1.New, key)}
}
```
