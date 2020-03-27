#/bin/sh

# Secure mode
set -e

# Keys dir
mkdir -p keys

# EC Key
openssl ecparam -name prime256v1 -genkey -noout -out keys/prime256v1-key.pem

# x509
openssl req -new -x509 -key keys/prime256v1-key.pem -out keys/server.pem -days 730

# AES entropy bits
head -c 48 /dev/random > keys/aes-key
