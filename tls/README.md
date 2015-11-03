# TLS

golang `crypto/tls` implements TLS 1.2

- client random + server random = pre-master secret
- pre-master secret -> master secret

master secret is used for symmetric key & Message Authentication Code(MAC) key & CBC Initial Vector(IV)

