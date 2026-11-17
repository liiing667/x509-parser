#!/bin/sh
# Regenerate the fixed certificate matrix used by tests/name_constraints.rs.
#
# Layout:
#   root.der            self-signed root CA (no constraints)
#   ca_<type>.der       intermediate CA with permitted+excluded subtrees
#   leaf_<type>_ok.der  leaf with SANs inside the permitted subtrees
#   leaf_<type>_excluded.der       leaf matching an excluded subtree
#   leaf_<type>_not_permitted.der  leaf outside all permitted subtrees
set -e
cd "$(dirname "$0")"

DAYS=3650

req() { # name, dn
    openssl req -new -newkey rsa:2048 -nodes -keyout "$1.key" \
        -out "$1.csr" -subj "$2" 2>/dev/null
}

mkroot() {
    openssl req -x509 -new -newkey rsa:2048 -nodes -keyout root.key \
        -out root.crt -days $DAYS -subj "/CN=NC Test Root" \
        -addext "basicConstraints=critical,CA:true" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}

mkca() { # name, constraints
    req "$1" "/CN=NC Test CA $1"
    printf 'basicConstraints=critical,CA:true,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nnameConstraints=critical,%s\n' "$2" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA root.crt -CAkey root.key -CAcreateserial \
        -out "$1.crt" -days $DAYS -extfile "$1.ext" 2>/dev/null
}

mkleaf() { # name, ca, san
    req "$1" "/CN=NC Test Leaf $1"
    printf 'basicConstraints=critical,CA:false\nsubjectAltName=%s\n' "$3" > "$1.ext"
    openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial \
        -out "$1.crt" -days $DAYS -extfile "$1.ext" 2>/dev/null
}

der() { openssl x509 -in "$1.crt" -outform DER -out "$1.der"; }

mkroot

mkca ca_dns   'permitted;DNS:.example.com,excluded;DNS:.blocked.example.com'
mkca ca_email 'permitted;email:.example.com,excluded;email:.blocked.example.com'
mkca ca_uri   'permitted;URI:.example.com,excluded;URI:.blocked.example.com'
mkca ca_ip    'permitted;IP:192.168.0.0/255.255.0.0,excluded;IP:192.168.66.0/255.255.255.0'

mkleaf leaf_dns_ok             ca_dns   'DNS:www.example.com'
mkleaf leaf_dns_excluded       ca_dns   'DNS:www.blocked.example.com'
mkleaf leaf_dns_not_permitted  ca_dns   'DNS:www.other.org'

mkleaf leaf_email_ok           ca_email 'email:user@mail.example.com'
mkleaf leaf_email_excluded     ca_email 'email:user@x.blocked.example.com'
mkleaf leaf_email_not_permitted ca_email 'email:user@other.org'

mkleaf leaf_uri_ok             ca_uri   'URI:https://www.example.com/path'
mkleaf leaf_uri_excluded       ca_uri   'URI:https://www.blocked.example.com/'
mkleaf leaf_uri_not_permitted  ca_uri   'URI:https://www.other.org/'

mkleaf leaf_ip_ok              ca_ip    'IP:192.168.1.2'
mkleaf leaf_ip_excluded        ca_ip    'IP:192.168.66.7'
mkleaf leaf_ip_not_permitted   ca_ip    'IP:10.0.0.1'

for f in root ca_dns ca_email ca_uri ca_ip \
    leaf_dns_ok leaf_dns_excluded leaf_dns_not_permitted \
    leaf_email_ok leaf_email_excluded leaf_email_not_permitted \
    leaf_uri_ok leaf_uri_excluded leaf_uri_not_permitted \
    leaf_ip_ok leaf_ip_excluded leaf_ip_not_permitted; do
    der "$f"
done

rm -f ./*.key ./*.csr ./*.crt ./*.ext ./*.srl
