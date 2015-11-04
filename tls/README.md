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

### preMasterSecret


###

```golang
func (hs *clientHandshakeState) establishKeys() error
```

```golang
// rsaKeyAgreement implements the standard TLS key agreement where the client
// encrypts the pre-master secret to the server's public key.
type rsaKeyAgreement struct{}

func (ka rsaKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) 

func (ka rsaKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error)
```
