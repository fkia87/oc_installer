#!/bin/bash

OCCONF=/etc/ocserv/ocserv.conf

function os {
DISTRO=$(cat /etc/os-release | grep -e '^ID=' \
| cut -d = -f 2 | sed -e 's/[[:punct:]]//g' \
| tr [:upper:] [:lower:])
echo $DISTRO
}

function install_pkg {
case $(os) in
centos)
    while ! rpm -q $1 >/dev/null 2>&1
    do
        echo "Installing $1..."
        yum -y install $1
        sleep 1
    done
;;
ubuntu)
    while ! dpkg -l | grep $1 >/dev/null 2>&1
    do
        echo "Installing $1..."
        apt update
        apt -y install $1
        sleep 1
    done
;;
esac
}

function firewall_cgf_ubuntu {
echo -e "Configuring ufw..."
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

echo -e "Opening ports..."
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

function find_mainif {
iflist=( $(find /sys/class/net/ | rev | cut -d / -f1 | rev | sed '/^$/d') )
tmp=( $(ip route |grep default |sed -e 's/^\s*//;s/\s/\n/g;') )

for var in "${tmp[@]}"; do
    [[ " ${iflist[*]} " =~ " ${var} " ]] && MAINIF=$var
done
if [[ -z $MAINIF ]]; then
    echo -e "\nCouldn't determine the main interface on the system.\n"
    exit 1
fi
}
#########################################
[[ $UID == "0" ]] || { echo "You are not root."; exit 1; }

echo "Checking net.ipv4.ip_forward..."
if grep '0' /proc/sys/net/ipv4/ip_forward >/dev/null; then
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p > /dev/null 2>&1
fi

[[ "$(os)" == "ubuntu" ]] && { apt update; install_pkg ufw; install_pkg gnutls-bin; }

[[ "$(os)" == "centos" ]] && { install_pkg gnutls-utils; install_pkg epel-release; }

install_pkg ocserv

read -p "Please enter your current ssh port number: [22] " SSH_PORT
[[ -z $SSH_PORT ]] && SSH_PORT=22
read -p "Please enter port number for OpenConnect server: [4444] " OC_PORT
[[ -z $OC_PORT ]] && OC_PORT=4444
read -p "Please enter domain name: [oc.example.com] " DOMAIN
[[ -z $DOMAIN ]] && DOMAIN=oc.example.com
EMAIL=admin@$(sed -e 's/^[[:alnum:]]*\.//' <<< $DOMAIN)
read -p "Enter VPN server IP address: [192.168.20.1] " IP
[[ -z $IP ]] && IP=192.168.20.1
NETWORK=$(sed -e 's/[[:digit:]]*$/0/' <<< $IP)
NETMASK=255.255.255.0
echo "Netmask is set to $NETMASK."

find_mainif

[[ "$(os)" == "ubuntu" ]] && firewall_cgf_ubuntu

[[ "$(os)" == "centos" ]] && firewall_cgf_centos

echo -e "Configuring ocserv..."
sed -ie 's/^\s*auth\s*=\s*.*/#&/g' $OCCONF
echo 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"' >> $OCCONF
sed -ie 's/^\s*tcp-port\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*udp-port\s*=\s*.*/#&/g' $OCCONF
echo "tcp-port = $OC_PORT" >> $OCCONF
sed -ie 's/^\s*try-mtu-discovery\s*=\s*.*/#&/g' $OCCONF
echo "try-mtu-discovery = true" >> $OCCONF
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
echo -e "Restarting ocserv service..."
systemctl restart ocserv

echo "Creating certificate directories..."
mkdir -p /etc/pki/ocserv/{cacerts,private,public}

echo "Generating keys and certificates..."
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

echo -e "Configuring ocserv..."
sed -ie 's/^\s*server-cert\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*server-key\s*=\s*.*/#&/g' $OCCONF
sed -ie 's/^\s*ca-cert\s*=\s*.*/#&/g' $OCCONF
cat << EOF >> $OCCONF
server-cert = /etc/pki/ocserv/public/server.crt
server-key = /etc/pki/ocserv/private/server.key
ca-cert = /etc/pki/ocserv/cacerts/ca.crt
EOF

echo -e "Restarting ocserv service..."
systemctl restart ocserv && echo -e "\n\
Successfully installed and configured \"ocserv\".\n
Use \"ocpasswd\" command to manage users:\n
Create:
ocpasswd <username>\n\n\
Delete:
ocpasswd -d <username>
"