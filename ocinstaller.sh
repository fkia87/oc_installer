#!/bin/bash

[[ $UID == "0" ]] || { echo "You are not root."; exit 1; }

files=("resources/pkg_management" "resources/os" "resources/network" "resources/bash_colors")

if ! [[ -f ${files[0]} ]] \
|| ! [[ -f ${files[1]} ]] \
|| ! [[ -f ${files[2]} ]] \
|| ! [[ -f ${files[3]} ]]; then
    rm -rf resources
    git clone https://github.com/fkia87/resources.git || \
    { echo -e "Error downloading required files from Github.
Check if \"Git\" is installed and your internet connection is OK." >&2; \
    exit 1; }
fi

for file in ${files[@]}; do
    source $file
done

OCCONF=/etc/ocserv/ocserv.conf

function firewall_cfg_ufw {
echo -e "${BLUE}Configuring firewall: \"ufw\"...${DECOLOR}"
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
    sed -i \
    "/allow dhcp client to work/ s/^/# allow forwarding for trusted network\n/" \
    /etc/ufw/before.rules
fi
if ! grep -e "-A ufw-before-forward -s $NETWORK/24 -j ACCEPT" \
  /etc/ufw/before.rules >/dev/null 2>&1; then
    sed -i \
    "/allow dhcp client to work/ s/^/-A ufw-before-forward -s $NETWORK\/24 -j ACCEPT\n/" \
    /etc/ufw/before.rules
fi
if ! grep -e "-A ufw-before-forward -d $NETWORK/24 -j ACCEPT" \
  /etc/ufw/before.rules >/dev/null 2>&1; then
    sed -i \
    "/allow dhcp client to work/ s/^/-A ufw-before-forward -d $NETWORK\/24 -j ACCEPT\n/" \
    /etc/ufw/before.rules
    sed -i "/allow dhcp client to work/ s/^/\n/" /etc/ufw/before.rules
fi

echo -e "${BLUE}Opening ports...${DECOLOR}"
ufw allow ${SSH_PORT},${OC_PORT}/tcp > /dev/null 2>&1
sed -i 's/ENABLED=no/ENABLED=yes/' /etc/ufw/ufw.conf
systemctl restart ufw
}

function firewall_cfg_firewalld {
echo -e "${BLUE}Configuring firewall: \"firewalld\"...${DECOLOR}"
firewall-cmd --version > /dev/null 2>&1 || { install_pkg firewalld; systemctl enable --now firewalld; }
firewall-cmd --permanent --add-port=${OC_PORT}/tcp
firewall-cmd --permanent --add-port=${SSH_PORT}/tcp
firewall-cmd --permanent --add-rich-rule=\
"rule family="ipv4" source address="$NETWORK/24" masquerade"
systemctl reload firewalld
}

function firewall_cfg_iptables {
echo -e "${BLUE}Configuring firewall: \"iptables\"...${DECOLOR}"
iptables -A INPUT -p tcp --dport ${OC_PORT} -j ACCEPT
iptables -A INPUT -p tcp --dport ${SSH_PORT} -j ACCEPT
iptables -A FORWARD -s ${NETWORK}/24 -j ACCEPT
iptables -A FORWARD -d ${NETWORK}/24 -j ACCEPT
iptables -t nat -A POSTROUTING -j MASQUERADE
mkdir -p /etc/iptables/
iptables-save > /etc/iptables/rules.v4 || \
echo -e "${RED}WARNING: \"iptables-save\" didn't work! rules will be lost after reboot!${DECOLOR}"
}

function print_help {
echo -e "\nUsage:                                $0 [-fw <firewall_name>] [-h]\n"
echo -e "Switches:\n"
echo "-fw, --firewall                       The name of the firewall you are currently using if needed"
echo -e "-h, --help                            Print this help\n"
}

# Processing switches #################################################################################
while (( $# > 0 )); do
    case $1 in
    --firewall|-fw)
        shift
        if [[ $1 == "iptables" ]] || [[ $1 == "ufw" ]] || [[ $1 == "firewalld" ]]; then
            FW=$1
        else
            echo -e "${RED}Invalid firewall name.${DECOLOR}"
            echo -e "${RED}Use either \"iptables\", \"ufw\" or \"firewalld\".${DECOLOR}"
            exit 1
        fi
        shift
        ;;
    --help|-h)
        print_help
    esac
done

#######################################################################################################

enable_ipforward

[[ "$(os)" == "ubuntu" ]] && install_pkg gnutls-bin ocserv
[[ "$(os)" == "centos" ]] && install_pkg gnutls-utils epel-release ocserv
[[ "$(os)" == "fedora" ]] && install_pkg gnutls-utils ocserv

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
read -p "Enter VPN server local IP address: [192.168.20.1] " IP
[[ -z $IP ]] && IP=192.168.20.1
while ! check_ipprivate $IP
do
    echo -e "${RED}Please enter a class C private IP address."
    echo -e "You can use an IP address within the range \
${BRED}192.168.0.0${RED} to ${BRED}192.168.255.255${RED}.${BLUE}"
    read -p "Enter VPN server local IP address: [192.168.20.1] " IP
    [[ -z $IP ]] && IP=192.168.20.1
done
NETWORK=$(sed -e 's/[[:digit:]]*$/0/' <<< $IP)
NETMASK=255.255.255.0
echo -e "Netmask is set to $NETMASK.${DECOLOR}"

find_mainif

if [[ -z $FW ]]; then
    [[ "$(os)" == "ubuntu" ]] && firewall_cfg_ufw
    [[ "$(os)" == "centos" ]] && firewall_cfg_firewalld
    [[ "$(os)" == "fedora" ]] && firewall_cfg_firewalld
else
    firewall_cfg_$FW
fi

echo -e "${BLUE}Configuring ocserv...${DECOLOR}"
sed -i 's/^\s*auth\s*=\s*.*/#&/g' $OCCONF
echo 'auth = "plain[passwd=/etc/ocserv/ocpasswd]"' >> $OCCONF
sed -i 's/^\s*tcp-port\s*=\s*.*/#&/g' $OCCONF
sed -i 's/^\s*udp-port\s*=\s*.*/#&/g' $OCCONF
echo "tcp-port = $OC_PORT" >> $OCCONF
sed -i 's/^\s*try-mtu-discovery\s*=\s*.*/#&/g' $OCCONF
echo "try-mtu-discovery = true" >> $OCCONF
sed -i 's/^\s*max-same-clients\s*=\s*.*/#&/g' $OCCONF
echo "max-same-clients = $SAME_CLIENTS" >> $OCCONF
sed -i 's/^\s*default-domain\s*=\s*.*/#&/g' $OCCONF
echo "default-domain = $DOMAIN" >> $OCCONF
sed -i 's/^\s*ipv4-network\s*=\s*.*/#&/g' $OCCONF
sed -i 's/^\s*ipv4-netmask\s*=\s*.*/#&/g' $OCCONF
echo "ipv4-network = $IP" >> $OCCONF
echo "ipv4-netmask = $NETMASK" >> $OCCONF
sed -i 's/^\s*tunnel-all-dns\s*=\s*.*/#&/g' $OCCONF
echo "tunnel-all-dns = true" >> $OCCONF
sed -i 's/^\s*dns\s*=\s*.*/#&/g' $OCCONF
echo -e "dns = 8.8.8.8\ndns = 4.2.2.4" >> $OCCONF
sed -i 's/^\s*route\s*=\s*.*/#&/g' $OCCONF
sed -i 's/^\s*no-route\s*=\s*.*/#&/g' $OCCONF
echo -e "${BLUE}Restarting ocserv service...${DECOLOR}"
systemctl restart ocserv

echo -e "${BLUE}Creating certificate directories..."
mkdir -p /etc/pki/ocserv/{cacerts,private,public}

echo -e "Generating keys and certificates...${DECOLOR}"
# Generate CA
certtool --generate-privkey --outfile /etc/pki/ocserv/private/ca.key >/dev/null 2>&1
cp templates/ca.tmpl /etc/pki/ocserv/cacerts/ca.tmpl
certtool --generate-self-signed \
--load-privkey /etc/pki/ocserv/private/ca.key \
--template /etc/pki/ocserv/cacerts/ca.tmpl \
--outfile /etc/pki/ocserv/cacerts/ca.crt >/dev/null 2>&1

# Generating a local server certificate
certtool --generate-privkey --outfile /etc/pki/ocserv/private/server.key >/dev/null 2>&1
cp templates/server.tmpl /etc/pki/ocserv/public/server.tmpl
certtool --generate-certificate \
--load-privkey /etc/pki/ocserv/private/server.key \
--load-ca-certificate /etc/pki/ocserv/cacerts/ca.crt \
--load-ca-privkey /etc/pki/ocserv/private/ca.key \
--template /etc/pki/ocserv/public/server.tmpl \
--outfile /etc/pki/ocserv/public/server.crt >/dev/null 2>&1

# Generating the client certificates
certtool --generate-privkey --outfile user.key >/dev/null 2>&1
cp templates/user.tmpl /etc/pki/ocserv/public/user.tmpl
certtool --generate-certificate --load-privkey user.key \
--load-ca-certificate /etc/pki/ocserv/cacerts/ca.crt \
--load-ca-privkey /etc/pki/ocserv/private/ca.key \
--template /etc/pki/ocserv/public/user.tmpl \
--outfile /etc/pki/ocserv/public/user.crt >/dev/null 2>&1

echo -e "${BLUE}Configuring ocserv...${DECOLOR}"
sed -i 's/^\s*server-cert\s*=\s*.*/#&/g' $OCCONF
sed -i 's/^\s*server-key\s*=\s*.*/#&/g' $OCCONF
sed -i 's/^\s*ca-cert\s*=\s*.*/#&/g' $OCCONF
cat << EOF >> $OCCONF
server-cert = /etc/pki/ocserv/public/server.crt
server-key = /etc/pki/ocserv/private/server.key
ca-cert = /etc/pki/ocserv/cacerts/ca.crt
EOF

echo -e "${BLUE}Restarting ocserv service...${DECOLOR}"
systemctl enable ocserv
systemctl restart ocserv && echo -e "${GREEN}\n\
Successfully installed and configured \"ocserv\".\n
Use ${BGREEN}\"ocpasswd\"${GREEN} command to manage users:\n
${YELLOW}Create:
ocpasswd <username>\n\n\
Delete:
ocpasswd -d <username>\n${DECOLOR}"