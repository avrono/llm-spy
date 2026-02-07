#!/bin/bash
# Copyright (c) 2026 llm-spy contributors
# SPDX-License-Identifier: MIT

set -e

# Create certs directory
mkdir -p certs
cd certs

# 1. Generate CA Private Key
if [ ! -f ca.key ]; then
    echo "Generating CA Private Key..."
    openssl genrsa -out ca.key 2048
fi

# 2. Generate CA Certificate (valid for 10 years)
# We MUST use a config file to enforce v3 extensions for Chrome
if [ ! -f ca.crt ]; then
    echo "Generating CA Certificate..."
    
    cat > ca.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions    = v3_ca
prompt             = no

[ req_distinguished_name ]
C  = US
ST = State
L  = City
O  = LLM-Spy-Proxy
CN = LLM-Spy-Root-CA

[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage         = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

    openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 -out ca.crt -config ca.cnf
    rm ca.cnf
fi

echo "✅ CA Certificate generated at $(pwd)/ca.crt"
echo "👉 Please import this file into Chrome/Chromium:"
echo "   Settings -> Privacy and security -> Security -> Manage device certificates -> Authorities -> Import"
echo "   (Make sure to check 'Trust this certificate for identifying websites')"
