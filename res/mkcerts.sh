# 生成rsa证书
CN="Test Server RSA Cert" openssl req -config ca.cnf -x509 -nodes \
	-keyout rsa_key.pem -out rsa_cert.pem -newkey rsa:2048 -days 3650
touch rsa_ca.pem
cat rsa_key.pem >> rsa_ca.pem
cat rsa_cert.pem >> rsa_ca.pem

# 生成512位的rsa密钥对
openssl genrsa -out rsa_export_key.pem 512 

# 生成dh密钥对
[ -f dhp.pem ] || openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 -out dhp.pem
# Now a DH private key
openssl genpkey -paramfile dhp.pem -out dh_key.pem
# Create DH public key file
openssl pkey -in dh_key.pem -pubout -out dhpub.pem

# 生成dsa证书
openssl dsaparam -out dsa_param.pem -genkey 1024
openssl gendsa -out dsa_key.pem dsa_param.pem
CN="Test Server DSA Cert" openssl req -config ca.cnf -x509 -new -key dsa_key.pem -out dsa_cert.pem
touch dsa_ca.pem
cat dsa_key.pem >> dsa_ca.pem
cat dsa_cert.pem >> dsa_ca.pem

# 生成带有dh参数的rsa证书
CN="Test Server DH Cert" openssl req -config ca.cnf -new -key rsa_ca.pem -out dhreq.pem
openssl x509 -req -in dhreq.pem -CA rsa_ca.pem -days 3600 \
	-force_pubkey dhpub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -out rsa_dhcert.pem

# 生成带有dh参数的dsa证书
CN="Test Server DSS DH Cert" openssl req -config ca.cnf -new -key dsa_ca.pem -out dhreq.pem
openssl x509 -req -in dhreq.pem -CA dsa_ca.pem -days 3600 \
	-force_pubkey dhpub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -out dsa_dhcert.pem

openssl ecparam -genkey -name secp192k1 -noout -out ecdh_key.pem
openssl pkey -in ecdh_key.pem -pubout -out ecdh_pubkey.pem

openssl ecparam -genkey -name secp192k1 -noout -out ecdsa_key.pem
CN="Test Server ECC Cert" openssl req -config ca.cnf -x509 -new -key ecdsa_key.pem -out ecdsa_cert.pem
touch ecdsa_ca.pem
cat ecdsa_key.pem >> ecdsa_ca.pem
cat ecdsa_cert.pem >> ecdsa_ca.pem

CN="Test Server ECDSA ECDH Cert" openssl req -config ca.cnf -new -key ecdsa_ca.pem -out ecdh_req.pem
openssl x509 -req -in ecdh_req.pem -CA ecdsa_ca.pem -days 3600 \
	-force_pubkey ecdh_pubkey.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -out ecdsa_ecdhcert.pem

CN="Test Server RSA ECDH Cert" openssl req -config ca.cnf -new -key rsa_ca.pem -out ecdh_req.pem
openssl x509 -req -in ecdh_req.pem -CA rsa_ca.pem -days 3600 \
	-force_pubkey ecdh_pubkey.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -out rsa_ecdhcert.pem

rm dhp.pem
rm dhreq.pem
rm ecdh_req.pem
rm dhpub.pem
rm ecdh_pubkey.pem
rm rsa_ca.pem
rm dsa_ca.pem
rm ecdsa_ca.pem
rm dsa_param.pem
rm rsa_ca.srl
rm dsa_ca.srl
rm ecdsa_ca.srl