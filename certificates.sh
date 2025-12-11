# 1. Create the Config file
echo "[req]
default_bits  = 2048
distinguished_name = req_distinguished_name
req_extensions = req_ext
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
CN = 127.0.0.1
[req_ext]
subjectAltName = @alt_names
[v3_req]
subjectAltName = @alt_names
[alt_names]
IP.1 = 127.0.0.1
DNS.1 = localhost" > san.cnf

# 2. Generate CA (Root) Key and Cert
openssl req -new -nodes -x509 -days 365 -keyout ca.key -out ca.crt -subj "/CN=MyRootCA"

# 3. Generate SERVER Key and CSR
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -config san.cnf

# 4. Sign SERVER Cert using CA (Includes SANs!)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365 -extensions v3_req -extfile san.cnf

# 5. Generate CLIENT Key and CSR
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=MyClient"

# 6. Sign CLIENT Cert using CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365

# 7. CLEANUP: The code needs to know whom to trust. 
#    In the Go code provided:
#    - Client trusts 'server.crt' (or CA). 
#    - Server trusts 'client.crt' (or CA).
#    
#    The Go code strictly loads:
#    SERVER uses `CLIENT_CERTFILE` (client.crt) as CA pool -> This is slightly wrong in standard PKI but works if self-signed.
#    CLIENT uses `SERVER_CERT` (server.crt) as CA pool.