mkdir -p keys
openssl ecparam -name prime256v1 -genkey -noout -out keys/prime256v1-key.pem
openssl req -new -x509 -key keys/prime256v1-key.pem -out keys/server.pem -days 730
head -c 48 /dev/random > keys/aes-key
