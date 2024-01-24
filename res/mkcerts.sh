# Root CA: create certificate directly
CN="Test Root CA" openssl req -config ca.cnf -x509 -nodes \
	-keyout root.pem -out root.pem -newkey rsa:2048 -days 3650

[ -f dhp.pem ] || openssl genpkey -genparam -algorithm DH -pkeyopt dh_paramgen_prime_len:1024 -out dhp.pem
# Now a DH private key
openssl genpkey -paramfile dhp.pem -out dhskey.pem
# Create DH public key file
openssl pkey -in dhskey.pem -pubout -out dhspub.pem
# Certificate request, key just reuses old one as it is ignored when the
# request is signed.
CN="Test Server DH Cert" openssl req -config ca.cnf -new \
	-key root.pem -out dhsreq.pem
# Sign request: end entity DH extensions
openssl x509 -req -in dhsreq.pem -CA root.pem -days 3600 \
	-force_pubkey dhspub.pem \
	-extfile ca.cnf -extensions dh_cert -CAcreateserial -out dhserver.pem

rm dhp.pem
rm dhsreq.pem