This document describes how the PKCS#7 test data files used by the
mbedTLS PKCS#7 extended verification APIs were generated.

These files are used to test PKCS#7 signature verification, certificate chain
validation, trust anchor handling, and multi-signer SignedData processing.

Generate Root CA (self‑signed)
openssl req -new -nodes -utf8 -sha256 -days 36500 -batch -x509 \
    -config root-ca.genkey \
    -out pkcs7-rsa-sha256-root-ca-1.pem \
    -keyout pkcs7-rsa-sha256-root-ca-1.key

Example root-ca.genkey:
[ req ]
default_bits = 4096
prompt = no
distinguished_name = req_distinguished_name
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
CN = PKCS7 Test Root CA

[ myexts ]
basicConstraints = CA:true
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer

Generate Intermediate CA
openssl req -new -nodes -utf8 -sha256 -batch \
    -config int-ca.genkey \
    -out int-ca.csr \
    -keyout pkcs7-rsa-sha256-int-ca-1.key

Example int-ca.genkey:
[ req ]
default_bits = 4096
prompt = no
distinguished_name = req_distinguished_name
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
CN = PKCS7 Test Intermediate CA

[ myexts ]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer

Sign Intermediate CA with Root CA
openssl x509 -req -sha256 \
    -CA pkcs7-rsa-sha256-root-ca-1.pem \
    -CAkey pkcs7-rsa-sha256-root-ca-1.key \
    -CAcreateserial \
    -days 36500 \
    -extfile int-ca.genkey \
    -extensions myexts \
    -in int-ca.csr \
    -out pkcs7-rsa-sha256-int-ca-1.der \
    -outform DER

optional PEM conversion:
openssl x509 -in pkcs7-rsa-sha256-int-ca-1.der -inform DER \
    -out pkcs7-rsa-sha256-int-ca-1.pem

Generate Leaf Signer Certificate
Create Leaf key and CSR
openssl req -new -nodes -utf8 -sha256 -batch \
    -config leaf.genkey \
    -out leaf.csr \
    -keyout pkcs7-rsa-sha256-leaf-1.key

Example leaf.genkey:
[ req ]
default_bits = 4096
prompt = no
distinguished_name = req_distinguished_name
string_mask = utf8only
x509_extensions = myexts

[ req_distinguished_name ]
CN = PKCS7 Test Leaf cert

[ myexts ]
basicConstraints = critical,CA:FALSE
keyUsage = digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid

Sign Leaf with Intermediate CA
openssl x509 -req -sha256 \
    -CA pkcs7-rsa-sha256-int-ca-1.der \
    -CAkey pkcs7-rsa-sha256-int-ca-1.key \
    -CAcreateserial \
    -days 36500 \
    -extfile leaf.genkey \
    -extensions myexts \
    -in leaf.csr \
    -out pkcs7-rsa-sha256-leaf-1.der \
    -outform DER

Generate PKCS#7 SignedData
Detached SignedData object using a zero-length input file. No certificates
are embedded in the PKCS#7 structure (-nocerts).
openssl cms -sign -binary -nocerts \
    -in pkcs7_zerolendata.bin \
    -signer pkcs7-rsa-sha256-leaf-1.der \
    -inkey pkcs7-rsa-sha256-leaf-1.key \
    -out pkcs7_zerolendata_detached-2.der \
    -outform DER -noattr -md sha256

Embed leaf certificate only
openssl cms -sign -binary \
    -in pkcs7_data.bin \
    -signer pkcs7-rsa-sha256-leaf-1.der \
    -inkey pkcs7-rsa-sha256-leaf-1.key \
    -out pkcs7_signed_cert_sha256.der \
    -outform DER -noattr -md sha256

Embed leaf + intermediate certificates
openssl cms -sign -binary \
    -in pkcs7_data.bin \
    -signer pkcs7-rsa-sha256-leaf-1.der \
    -inkey pkcs7-rsa-sha256-leaf-1.key \
    -certfile pkcs7-rsa-sha256-int-ca-1.der \
    -out pkcs7_signed_cert_sha256-2.der \
    -outform DER -noattr -md sha256

Detached signature with no embedded certificates
openssl cms -sign -binary -nocerts \
    -in pkcs7_data.bin \
    -signer pkcs7-rsa-sha256-leaf-1.der \
    -inkey pkcs7-rsa-sha256-leaf-1.key \
    -out pkcs7_signed_without_cert.der \
    -outform DER -noattr -md sha256

Multiple Signers
openssl cms -sign -binary \
    -in pkcs7_data.bin \
    -signer pkcs7-rsa-sha256-leaf-1.der \
    -inkey pkcs7-rsa-sha256-leaf-1.key \
    -signer pkcs7-rsa-sha256-leaf-2.der \
    -inkey pkcs7-rsa-sha256-leaf-2.key \
    -out pkcs7_signed_cert_sha256-3.der \
    -outform DER -noattr -md sha256

Multiple signers with embedded intermediates
cat pkcs7-rsa-sha256-int-ca-1.pem \
    pkcs7-rsa-sha256-int-ca-2.pem \
    > pkcs7-rsa-sha256-int-ca-chain.pem

openssl cms -sign -binary \
    -in pkcs7_data.bin \
    -signer pkcs7-rsa-sha256-leaf-2.der \
    -inkey pkcs7-rsa-sha256-leaf-2.key \
    -signer pkcs7-rsa-sha256-leaf-3.der \
    -inkey pkcs7-rsa-sha256-leaf-3.key \
    -certfile pkcs7-rsa-sha256-int-ca-chain.pem \
    -out pkcs7_signed_multi_cert_sha256.der \
    -outform DER -noattr -md sha256

Generate a leaf certificate signed directly by the Root CA using the same steps
procedure as above, then generate the PKCS#7 SignedData
openssl cms -sign -binary \
    -in pkcs7_data.bin \
    -signer pkcs7-rsa-sha256-leaf-4.der \
    -inkey pkcs7-rsa-sha256-leaf-4.key \
    -out pkcs7_signed_cert_sha256-4.der \
    -outform DER -noattr -md sha256

Create CA Chain Bundle
cat pkcs7-rsa-sha256-int-ca-1.pem \
    pkcs7-rsa-sha256-root-ca-1.pem \
    > pkcs7-rsa-sha256-ca-chain.pem

To validate certificate chain verification behavior under different
conditions, the test data includes several certificate chain:
Root CA -> Intermediate CA -> Leaf Certificate
Root-ca-1 -> Int-ca-1 -> Leaf-1
Root-ca-1 -> Int-ca-3 -> Leaf-3

Root CA -> Multiple Intermediate CAs -> Leaf Certificate
Root-ca-1 -> Int-ca-1 -> Int-ca-2 -> Leaf-2

Root CA -> Leaf Certificate
Root-ca-1 -> Leaf-4

Root-ca-1: pkcs7-rsa-sha256-root-ca-1.pem aka "CN = PKCS7 Test Root CA"
Int-ca-1: pkcs7-rsa-sha256-int-ca-1.der  aka "CN = PKCS7 Test Intermediate CA"
Int-ca-2: pkcs7-rsa-sha256-int-ca-2.der  aka "CN = PKCS7 Test Intermediate CA 2"
Int-ca-3: pkcs7-rsa-sha256-int-ca-3.der  aka "CN = PKCS7 Test Intermediate CA 3"
Leaf-1: pkcs7-rsa-sha256-leaf-1.der aka "CN = PKCS7 Test Leaf cert"
Leaf-2: pkcs7-rsa-sha256-leaf-2.der aka "CN = PKCS7 Test Leaf cert 2"
Leaf-3: pkcs7-rsa-sha256-leaf-3.der aka "CN = PKCS7 Test Leaf cert 3"
Leaf-4: pkcs7-rsa-sha256-leaf-4.der aka "CN = PKCS7 Test Leaf cert 4"
