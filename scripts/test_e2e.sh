#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$DIR/.."

echo "======= 1. Generating PKI ======="
"$DIR/generate_pki.sh"

echo "======= 2. Starting Docker Services ======="
cd "$ROOT_DIR"
docker-compose -f docker-compose.test.yml down -v || true
docker-compose -f docker-compose.test.yml up -d --build

echo "Waiting for services to spin up..."
sleep 5

echo "======= 3. Executing CA 1 Tests (2-tier) ======="
echo "-> Testing CA 1 CRL Download"
crl1=$(curl -s http://localhost:8080/crls/ca1.crl | openssl crl -inform PEM -text -noout | grep "Revoked Certificates:" -A 5 || true)
if [[ "$crl1" == *"Revoked Certificates:"* ]]; then
    echo "[PASS] CA 1 CRL"
else
    echo "[FAIL] CA 1 CRL"
    exit 1
fi

echo "-> Testing CA 1 OCSP Valid Client"
openssl ocsp -CAfile test-data/cas/ca1.pem -issuer test-data/cas/ca1.pem -cert test-data/clients/ca1-valid.pem -url http://localhost:8080/ocsp -VAfile test-data/responders/ca1-ocsp.pem > /tmp/ca1-valid.log 2>&1
if grep -q "valid.pem: good" /tmp/ca1-valid.log; then
    echo "[PASS] CA 1 Valid Client"
else
    echo "[FAIL] CA 1 Valid Client"
    cat /tmp/ca1-valid.log
    exit 1
fi

echo "-> Testing CA 1 OCSP Revoked Client"
openssl ocsp -CAfile test-data/cas/ca1.pem -issuer test-data/cas/ca1.pem -cert test-data/clients/ca1-revoked.pem -url http://localhost:8080/ocsp -VAfile test-data/responders/ca1-ocsp.pem > /tmp/ca1-revoked.log 2>&1
if grep -q "revoked.pem: revoked" /tmp/ca1-revoked.log; then
    echo "[PASS] CA 1 Revoked Client"
else
    echo "[FAIL] CA 1 Revoked Client"
    cat /tmp/ca1-revoked.log
    exit 1
fi

echo "======= 4. Executing CA 2 Tests (3-tier) ======="
echo "-> Testing CA 2 CRL Download"
crl2=$(curl -s http://localhost:8080/crls/ca2.crl | openssl crl -inform PEM -text -noout | grep "Revoked Certificates:" -A 5 || true)
if [[ "$crl2" == *"Revoked Certificates:"* ]]; then
    echo "[PASS] CA 2 CRL"
else
    echo "[FAIL] CA 2 CRL"
    exit 1
fi

echo "-> Testing CA 2 OCSP Valid Client"
# The issuer is the intermediate CA that signed the client cert
openssl ocsp -CAfile test-data/cas/ca2-chain.pem -issuer test-data/cas/ca2-inter.pem -cert test-data/clients/ca2-valid.pem -url http://localhost:8080/ocsp -VAfile test-data/responders/ca2-ocsp.pem > /tmp/ca2-valid.log 2>&1
if grep -q "valid.pem: good" /tmp/ca2-valid.log; then
    echo "[PASS] CA 2 Valid Client"
else
    echo "[FAIL] CA 2 Valid Client"
    cat /tmp/ca2-valid.log
    exit 1
fi

echo "-> Testing CA 2 OCSP Revoked Client"
openssl ocsp -CAfile test-data/cas/ca2-chain.pem -issuer test-data/cas/ca2-inter.pem -cert test-data/clients/ca2-revoked.pem -url http://localhost:8080/ocsp -VAfile test-data/responders/ca2-ocsp.pem > /tmp/ca2-revoked.log 2>&1
if grep -q "revoked.pem: revoked" /tmp/ca2-revoked.log; then
    echo "[PASS] CA 2 Revoked Client"
else
    echo "[FAIL] CA 2 Revoked Client"
    cat /tmp/ca2-revoked.log
    exit 1
fi

echo "======= ALL TESTS PASSED ======="
docker-compose -f docker-compose.test.yml down -v
