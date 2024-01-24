# 生成rsa证书
CN="Test RSA Root CA" openssl req -config ca.cnf -x509 -nodes \
	-keyout rsa_key.pem -out rsa_cert.pem -newkey rsa:2048 -days 3650
touch rsa_ca.pem
cat rsa_key.pem >> rsa_ca.pem
cat rsa_cert.pem >> rsa_ca.pem

# 生成dh密钥对
[ -f dhp.pem ] || openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 -out dhp.pem
# Now a DH private key
openssl genpkey -paramfile dhp.pem -outform der -out dhkey.der
# Create DH public key file
openssl pkey -inform der -in dhkey.der -pubout -out dhspub.pem

# 生成dsa证书
openssl dsaparam -out dsa_key.pem -genkey 1024
openssl req -config ca.cnf -x509 -new -key dsa_key.pem -out dsa_cert.pem
touch dsa_ca.pem
cat dsa_key.pem >> dsa_ca.pem
cat dsa_cert.pem >> dsa_ca.pem

# 生成带有dh参数的rsa证书
CN="Test Server DH Cert" openssl req -config ca.cnf -new \
	-key rsa_ca.pem -out dhsreq.pem
openssl x509 -req -in dhsreq.pem -CA rsa_ca.pem -days 3600 \
	-force_pubkey dhspub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -outform der -out rsa_dhcert.der

# 生成带有dh参数的dsa证书
CN="Test Server DSS DH Cert" openssl req -config ca.cnf -new \
	-key dsa_ca.pem -out dhsreq.pem
openssl x509 -req -in dhsreq.pem -CA dsa_ca.pem -days 3600 \
	-force_pubkey dhspub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -outform der -out dsa_dhcert.der

rm dhp.pem
rm dhsreq.pem
rm dhspub.pem
rm rsa_ca.pem
rm dsa_ca.pem
rm rsa_ca.srl
rm dsa_ca.srl

openssl x509 -in rsa_cert.pem -outform der -out rsa_cert.der
openssl x509 -in dsa_cert.pem -outform der -out dsa_cert.der

rm rsa_cert.pem
rm dsa_cert.pem