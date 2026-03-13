#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TEST_DATA_DIR="$DIR/../test-data"
mkdir -p "$TEST_DATA_DIR/cas"
mkdir -p "$TEST_DATA_DIR/responders"
mkdir -p "$TEST_DATA_DIR/crls"
mkdir -p "$TEST_DATA_DIR/clients"

# Clean out the old directories
rm -rf "$TEST_DATA_DIR/cas"/*
rm -rf "$TEST_DATA_DIR/responders"/*
rm -rf "$TEST_DATA_DIR/crls"/*
rm -rf "$TEST_DATA_DIR/clients"/*

cd "$TEST_DATA_DIR"

echo "Generating test PKI..."

# Boilerplate configuration template for x509 extensions
cat > openssl.cnf <<EOF
[ v3_ca ]
basicConstraints = critical, CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign

[ v3_ocsp ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = OCSPSigning

[ v3_client ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
EOF

# ==========================================
# CA 1 Topology (2-tier: Root -> Client/OCSP)
# ==========================================
echo "=> Setting up CA1 (2-tier PKI)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout cas/ca1-key.pem -out cas/ca1.pem -subj "/CN=CA1-Root" -days 365 -config openssl.cnf -extensions v3_ca

# CA1 OCSP Responder
openssl req -newkey rsa:2048 -nodes -keyout responders/ca1-ocsp-key.pem -out ca1-ocsp.csr -subj "/CN=CA1-Responder"
openssl x509 -req -in ca1-ocsp.csr -CA cas/ca1.pem -CAkey cas/ca1-key.pem -CAcreateserial -out responders/ca1-ocsp.pem -days 365 -extfile openssl.cnf -extensions v3_ocsp

# CA1 Valid Client
openssl req -newkey rsa:2048 -nodes -keyout clients/ca1-valid-key.pem -out ca1-valid.csr -subj "/CN=CA1-Valid-Client"
openssl x509 -req -in ca1-valid.csr -CA cas/ca1.pem -CAkey cas/ca1-key.pem -CAcreateserial -out clients/ca1-valid.pem -days 365 -extfile openssl.cnf -extensions v3_client

# CA1 Revoked Client
openssl req -newkey rsa:2048 -nodes -keyout clients/ca1-revoked-key.pem -out ca1-revoked.csr -subj "/CN=CA1-Revoked-Client"
openssl x509 -req -in ca1-revoked.csr -CA cas/ca1.pem -CAkey cas/ca1-key.pem -CAcreateserial -out clients/ca1-revoked.pem -days 365 -extfile openssl.cnf -extensions v3_client

# Generate CRL for CA1 with the revoked certificate serial
# We generate a blank database so openssl ca commands can be used for native revocation, or manually generate the CRL.
# Using a quick python/openssl hack to create a blank database and index file for robust CRL generation
mkdir -p ca1_db
touch ca1_db/index.txt
echo "1000" > ca1_db/serial
echo "1000" > ca1_db/crlnumber

cat > ca1.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = ./ca1_db
database = \$dir/index.txt
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_crl_days= 30
certificate = cas/ca1.pem
private_key = cas/ca1-key.pem
EOF

openssl ca -valid clients/ca1-valid.pem -config ca1.cnf || true
openssl ca -revoke clients/ca1-revoked.pem -config ca1.cnf
openssl ca -gencrl -out crls/ca1.crl -config ca1.cnf

# ==========================================
# CA 2 Topology (3-tier: Root -> Inter -> Client/OCSP)
# ==========================================
echo "=> Setting up CA2 (3-tier PKI)"
openssl req -x509 -newkey rsa:2048 -nodes -keyout cas/ca2-root-key.pem -out cas/ca2-root.pem -subj "/CN=CA2-Root" -days 365 -config openssl.cnf -extensions v3_ca

# CA2 Intermediate
openssl req -newkey rsa:2048 -nodes -keyout cas/ca2-inter-key.pem -out ca2-inter.csr -subj "/CN=CA2-Intermediate"
openssl x509 -req -in ca2-inter.csr -CA cas/ca2-root.pem -CAkey cas/ca2-root-key.pem -CAcreateserial -out cas/ca2-inter.pem -days 365 -extfile openssl.cnf -extensions v3_ca

# CA2 Bundles
cat cas/ca2-inter.pem cas/ca2-root.pem > cas/ca2-chain.pem

# CA2 OCSP Responder
openssl req -newkey rsa:2048 -nodes -keyout responders/ca2-ocsp-key.pem -out ca2-ocsp.csr -subj "/CN=CA2-Responder"
openssl x509 -req -in ca2-ocsp.csr -CA cas/ca2-inter.pem -CAkey cas/ca2-inter-key.pem -CAcreateserial -out responders/ca2-ocsp.pem -days 365 -extfile openssl.cnf -extensions v3_ocsp

# CA2 Valid Client
openssl req -newkey rsa:2048 -nodes -keyout clients/ca2-valid-key.pem -out ca2-valid.csr -subj "/CN=CA2-Valid-Client"
openssl x509 -req -in ca2-valid.csr -CA cas/ca2-inter.pem -CAkey cas/ca2-inter-key.pem -CAcreateserial -out clients/ca2-valid.pem -days 365 -extfile openssl.cnf -extensions v3_client

# CA2 Revoked Client
openssl req -newkey rsa:2048 -nodes -keyout clients/ca2-revoked-key.pem -out ca2-revoked.csr -subj "/CN=CA2-Revoked-Client"
openssl x509 -req -in ca2-revoked.csr -CA cas/ca2-inter.pem -CAkey cas/ca2-inter-key.pem -CAcreateserial -out clients/ca2-revoked.pem -days 365 -extfile openssl.cnf -extensions v3_client

# CRL for CA2 Intermediate
mkdir -p ca2_db
touch ca2_db/index.txt
echo "1000" > ca2_db/serial
echo "1000" > ca2_db/crlnumber

cat > ca2.cnf <<EOF
[ ca ]
default_ca = CA_default

[ CA_default ]
dir = ./ca2_db
database = \$dir/index.txt
serial = \$dir/serial
crlnumber = \$dir/crlnumber
default_md = sha256
default_crl_days= 30
certificate = cas/ca2-inter.pem
private_key = cas/ca2-inter-key.pem
EOF

openssl ca -valid clients/ca2-valid.pem -config ca2.cnf || true
openssl ca -revoke clients/ca2-revoked.pem -config ca2.cnf
openssl ca -gencrl -out crls/ca2.crl -config ca2.cnf

# Cleanup scaffolding
rm ca*.csr openssl.cnf ca*.cnf cas/*.srl
rm -rf ca1_db ca2_db

# Ensure all files are readable by the non-root container user (UID 1001)
find . -type f -exec chmod 644 {} +
find . -type d -exec chmod 755 {} +

echo "PKI Generation Complete. Files located in $TEST_DATA_DIR"
