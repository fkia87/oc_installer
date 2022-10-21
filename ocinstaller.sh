#!/bin/bash

source resources/os
source resources/network
source resources/pkg_management
source resources/bash_colors

OCCONF=/etc/ocserv/ocserv.conf

function firewall_cgf_ubuntu {
echo -e "${BLUE}Configuring ufw...${DECOLOR}"
if ! grep -e "-A POSTROUTING -s $NETWORK/24 -o $MAINIF -j MASQUERADE" \
  /etc/ufw/before.rules >/dev/null 2>&1; then
    cat << EOF >> /etc/ufw/before.rules

# NAT table rules
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $NETWORK/24 -o $MAINIF -j MASQUERADE

# End each table with the 'COMMIT' line or these rules won't be processed
COMMIT
EOF
fi

# Adding required firewall rules
if ! grep -e "# allow forwarding for trusted network" \
  /etc/ufw/before.rules >/dev/null 2>&1; then
    sed -ie \
    "/allow dhcp client to work/ s/^/# allow forwarding for trusted network\n/" \
    /etc/ufw/before.rules
fi
if ! grep -e "-A ufw-before-forward -s $NETWORK/24 -j ACCEPT" \
  /etc/ufw/before.rules >/dev/null 2>&1; then
    sed -ie \
    "/allow dhcp client to work/ s/^/-A ufw-before-forward -s $NETWORK\/24 -j ACCEPT\n/" \
    /etc/ufw/before.rules
fi
if ! grep -e "-A ufw-before-forward -d $NETWORK/24 -j ACCEPT" \
  /etc/ufw/before.rules >/dev/null 2>&1; then
    sed -ie \
    "/allow dhcp client to work/ s/^/-A ufw-before-forward -d $NETWORK\/24 -j ACCEPT\n/" \
    /etc/ufw/before.rules
    sed -ie "/allow dhcp client to work/ s/^/\n/" /etc/ufw/before.rules
fi

echo -e "${BLUE}Opening ports...${DECOLOR}"
ufw allow ${SSH_PORT},${OC_PORT}/tcp > /dev/null 2>&1
sed -ie 's/ENABLED=no/ENABLED=yes/' /etc/ufw/ufw.conf
systemctl restart ufw
}

function firewall_cgf_centos {
firewall-cmd --permanent --add-port=${OC_PORT}/tcp
firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
firewall-cmd --permanent --add-rich-rule=\
"rule family="ipv4" source address="$NETWORK/24" masquerade"
systemctl reload firewalld
}

#########################################
checkuser

enable_ipforward

[[ "$(os)" == "ubuntu" ]] && { apt update; install_pkg ufw; install_pkg gnutls-bin; }

[[ "$(os)" == "centos" ]] && { install_pkg gnutls-utils; install_pkg epel-release; }

install_pkg ocserv

echo -e "${BLUE}"
read -p "Please enter your current ssh port number: [22] " SSH_PORT
[[ -z $SSH_PORT ]] && SSH_PORT=22
read -p "Please enter port number for OpenConnect server: [4444] " OC_PORT
[[ -z $OC_PORT ]] && OC_PORT=4444
read -p "Please enter maximum number of same clients: [2] " SAME_CLIENTS
[[ -z $SAME_CLIENTS ]] && SAME_CLIENTS=2
read -p "Please enter domain name: [oc.example.com] " DOMAIN
[[ -z $DOMAIN ]] && DOMAIN=oc.example.com
EMAIL=admin@$(sed -e 's/^[[:alnum:]]*\.//' <<< $DOMAIN)
read -p "Enter VPN server IP address: [192.168.20.1] " IP
[[ -z $IP ]] && IP=192.168.20.1
NETWORK=$(sed -e 's/[[:digit:]]*$/0/' <<< $IP)
NETMASK=255.255.255.0
echo -e "Netmask is set to $NETMASK.${DECOLOR}"

find_mainif

[[ "$(os)" == "ubuntu" ]] && firewall_cgf_ubuntu >/dev/null 2>&1

[[ "$(os)" == "centos" ]] && firewall_cgf_centos >/dev/null 2>&1

echo -e "${BLUE}Configuring ocserv...${DECOLOR}"
sed -ie 's/^\s*auth\s*=\s*.*/#&/g' $OCCONF
echo 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"' >> $OCCONF
sed -ie 's/^\s*tcp-port\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*udp-port\s*=\s*.*/#&/g' $OCCONF
echo "tcp-port = $OC_PORT" >> $OCCONF
sed -ie 's/^\s*try-mtu-discovery\s*=\s*.*/#&/g' $OCCONF
echo "try-mtu-discovery = true" >> $OCCONF
sed -ie 's/^\s*max-same-clients\s*=\s*.*/#&/g' $OCCONF
echo "max-same-clients = $SAME_CLIENTS" >> $OCCONF
sed -ie 's/^\s*default-domain\s*=\s*.*/#&/g' $OCCONF
echo "default-domain = $DOMAIN" >> $OCCONF
sed -ie 's/^\s*ipv4-network\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*ipv4-netmask\s*=\s*.*/#&/g' $OCCONF
echo "ipv4-network = $IP" >> $OCCONF
echo "ipv4-netmask = $NETMASK" >> $OCCONF
sed -ie 's/^\s*tunnel-all-dns\s*=\s*.*/#&/g' $OCCONF
echo "tunnel-all-dns = true" >> $OCCONF
sed -ie 's/^\s*dns\s*=\s*.*/#&/g' $OCCONF
echo -e "dns = 8.8.8.8\ndns = 4.2.2.4" >> $OCCONF
sed -ie 's/^\s*route\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*no-route\s*=\s*.*/#&/g' $OCCONF
echo -e "${BLUE}Restarting ocserv service...${DECOLOR}"
systemctl restart ocserv

echo -e "${BLUE}Creating certificate directories..."
mkdir -p /etc/pki/ocserv/{cacerts,private,public}

echo -e "Generating keys and certificates...${DECOLOR}"
# Generate CA
certtool --generate-privkey --outfile /etc/pki/ocserv/private/ca.key >/dev/null 2>&1
cat << EOF > /etc/pki/ocserv/cacerts/ca.tmpl
cn = "AnyConnect VPN CA"
organization = "myocserv"
serial = 1
expiration_days = -1
ca
signing_key
cert_signing_key
crl_signing_key
EOF
certtool --generate-self-signed \
--load-privkey /etc/pki/ocserv/private/ca.key \
--template /etc/pki/ocserv/cacerts/ca.tmpl \
--outfile /etc/pki/ocserv/cacerts/ca.crt >/dev/null 2>&1

# Generating a local server certificate
certtool --generate-privkey --outfile /etc/pki/ocserv/private/server.key >/dev/null 2>&1
cat << EOF > /etc/pki/ocserv/public/server.tmpl
cn = "AnyConnect VPN Server"
dns_name = "www.myocserv.com"
organization = "myocserv"
expiration_days = -1
signing_key
encryption_key
tls_www_server
EOF
certtool --generate-certificate \
--load-privkey /etc/pki/ocserv/private/server.key \
--load-ca-certificate /etc/pki/ocserv/cacerts/ca.crt \
--load-ca-privkey /etc/pki/ocserv/private/ca.key \
--template /etc/pki/ocserv/public/server.tmpl \
--outfile /etc/pki/ocserv/public/server.crt >/dev/null 2>&1

# Generating the client certificates
certtool --generate-privkey --outfile user.key >/dev/null 2>&1
cat << EOF > /etc/pki/ocserv/public/user.tmpl
cn = "AnyConnect VPN User"
unit = "admins"
expiration_days = -1
signing_key
tls_www_client
EOF
certtool --generate-certificate --load-privkey user.key \
--load-ca-certificate /etc/pki/ocserv/cacerts/ca.crt \
--load-ca-privkey /etc/pki/ocserv/private/ca.key \
--template /etc/pki/ocserv/public/user.tmpl \
--outfile /etc/pki/ocserv/public/user.crt >/dev/null 2>&1

echo -e "${BLUE}Configuring ocserv...${DECOLOR}"
sed -ie 's/^\s*server-cert\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*server-key\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*ca-cert\s*=\s*.*/#&/g' $OCCONF
cat << EOF >> $OCCONF
server-cert = /etc/pki/ocserv/public/server.crt
server-key = /etc/pki/ocserv/private/server.key
ca-cert = /etc/pki/ocserv/cacerts/ca.crt
EOF

echo -e "${BLUE}Restarting ocserv service...${DECOLOR}"
systemctl restart ocserv && echo -e "${GREEN}\n\
Successfully installed and configured \"ocserv\".\n
Use ${BGREEN}\"ocpasswd\"${GREEN} command to manage users:\n
${YELLOW}Create:
ocpasswd <username>\n\n\
Delete:
ocpasswd -d <username>\n${DECOLOR}"