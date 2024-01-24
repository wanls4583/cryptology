# Root CA: create certificate directly
CN="Test Root CA" openssl req -config ca.cnf -x509 -nodes \
	-keyout rsa_ca.pem -out rsa_ca.pem -newkey rsa:2048 -days 3650

[ -f dhp.pem ] || openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 -out dhp.pem
# Now a DH private key
openssl genpkey -paramfile dhp.pem -outform der -out dhkey.der
# Create DH public key file
openssl pkey -inform der -in dhkey.der -pubout -out dhspub.pem
# Certificate request, key just reuses old one as it is ignored when the
# request is signed.
CN="Test Server DH Cert" openssl req -config ca.cnf -new \
	-key rsa_ca.pem -out dhsreq.pem
# Sign request: end entity DH extensions
openssl x509 -req -in dhsreq.pem -CA rsa_ca.pem -days 3600 \
	-force_pubkey dhspub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -outform der -out dhcert.der


CN="Test Server DSS DH Cert" openssl req -config ca.cnf -new \
	-key dsa_ca.pem -out dhsreq.pem
openssl x509 -req -in dhsreq.pem -CA dsa_ca.pem -days 3600 \
	-force_pubkey dhspub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -outform der -out dsa_dhcert.der

rm dhp.pem
rm dhsreq.pem
rm dhspub.pem
rm rsa_ca.srl
rm dsa_ca.srl