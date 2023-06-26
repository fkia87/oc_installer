#!/bin/bash
# shellcheck disable=SC2068,SC1090,SC2001

# IMPORT REQUIREMENTS ############################################################################################
requirements=("resources/bash_colors" "resources/utils" "resources/loading" "resources/network")
for ((i=0; i<${#requirements[@]}; i++)); do
    if ! [[ -d resources ]] || ! [[ -f ${requirements[i]} ]]; then
        rm -rf resources
        wget https://github.com/fkia87/resources/archive/refs/heads/master.zip || \
        { echo -e "Error downloading required files from Github." >&2; exit 1; }
        unzip master.zip || { echo -e "Command \"unzip master.zip\" failed." >&2; exit 1; }
        mv resources* resources
        break
    fi
done

for file in ${requirements[@]}; do
    source "$file"
done

##################################################################################################################

OCCONF=/etc/ocserv/ocserv.conf
keys_dir=/etc/pki/ocserv

firewall_cfg_ufw() {
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
ufw allow "${SSH_PORT}","${OC_PORT}"/tcp > /dev/null 2>&1
sed -i 's/ENABLED=no/ENABLED=yes/' /etc/ufw/ufw.conf
systemctl restart ufw
}

firewall_cfg_firewalld() {
echo -e "${BLUE}Configuring firewall: \"firewalld\"...${DECOLOR}"
firewall-cmd --version > /dev/null 2>&1 || { install_pkg firewalld; systemctl enable --now firewalld; }
firewall-cmd --permanent --add-port="${OC_PORT}"/tcp
firewall-cmd --permanent --add-port="${SSH_PORT}"/tcp
firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$NETWORK/24\" masquerade"
systemctl reload firewalld
}

firewall_cfg_iptables() {
echo -e "${BLUE}Configuring firewall: \"iptables\"...${DECOLOR}"
iptables -A INPUT -p tcp --dport "${OC_PORT}" -j ACCEPT
iptables -A INPUT -p tcp --dport "${SSH_PORT}" -j ACCEPT
iptables -A FORWARD -s "${NETWORK}"/24 -j ACCEPT
iptables -A FORWARD -d "${NETWORK}"/24 -j ACCEPT
iptables -t nat -A POSTROUTING -j MASQUERADE
mkdir -p /etc/iptables/
iptables-save > /etc/iptables/rules.v4
[[ -f /etc/sysconfig/iptables ]] && iptables-save > /etc/sysconfig/iptables
}

print_help() {
echo -e "\nUsage:                                $0 [-fw <firewall_name>] [-h]\n"
echo -e "Switches:\n"
echo -e "-fw, --firewall                       The name of the firewall you are currently using"
echo -e "                                      Supported values: ufw, firewalld, iptables"
echo -e "-h, --help                            Print this help\n"
}

# Generate CA
gen_ca() {
    certtool --generate-privkey --outfile $keys_dir/private/ca.key >/dev/null 2>&1
    cp templates/ca.tmpl $keys_dir/cacerts/ca.tmpl
    certtool --generate-self-signed \
    --load-privkey $keys_dir/private/ca.key \
    --template $keys_dir/cacerts/ca.tmpl \
    --outfile $keys_dir/cacerts/ca.crt >/dev/null 2>&1
}

# Generating a local server certificate
gen_server_crt() {
    certtool --generate-privkey --outfile $keys_dir/private/server.key >/dev/null 2>&1
    cp templates/server.tmpl $keys_dir/public/server.tmpl
    certtool --generate-certificate \
    --load-privkey $keys_dir/private/server.key \
    --load-ca-certificate $keys_dir/cacerts/ca.crt \
    --load-ca-privkey $keys_dir/private/ca.key \
    --template $keys_dir/public/server.tmpl \
    --outfile $keys_dir/public/server.crt >/dev/null 2>&1
}

# Generating the client certificates
gen_user_crt() {
    certtool --generate-privkey --outfile user.key >/dev/null 2>&1
    cp templates/user.tmpl $keys_dir/public/user.tmpl
    certtool --generate-certificate --load-privkey user.key \
    --load-ca-certificate $keys_dir/cacerts/ca.crt \
    --load-ca-privkey $keys_dir/private/ca.key \
    --template $keys_dir/public/user.tmpl \
    --outfile $keys_dir/public/user.crt >/dev/null 2>&1   
}

# Processing switches #################################################################################
while (( $# > 0 )); do
    case $1 in
        --firewall|-fw)
            if [[ $2 == "iptables" ]] || [[ $2 == "ufw" ]] || [[ $2 == "firewalld" ]]; then
                FW=$2
            else
                err "${RED}Unsupported firewall name. Run \"$0 -h\" for more info.${DECOLOR}"
            fi
            shift 2
            ;;
        --help|-h)
            print_help
    esac
done

#######################################################################################################
checkuser

enable_ipforward

case $(os) in
    ubuntu)
        install_pkg gnutls-bin ocserv
        ;;
    centos | almalinux | rocky)
        install_pkg gnutls-utils epel-release && install_pkg ocserv
        ;;
    fedora)
        install_pkg gnutls-utils ocserv
        ;;
esac

read -r -p "Please enter your current ssh port number: [22] " SSH_PORT
[[ -z $SSH_PORT ]] && SSH_PORT=22
read -r -p "Please enter port number for OpenConnect server: [4444] " OC_PORT
[[ -z $OC_PORT ]] && OC_PORT=4444
read -r -p "Please enter maximum number of same clients: [2] " SAME_CLIENTS
[[ -z $SAME_CLIENTS ]] && SAME_CLIENTS=2
read -r -p "Please enter domain name: [oc.example.com] " DOMAIN
[[ -z $DOMAIN ]] && DOMAIN=oc.example.com
# EMAIL=admin@$(sed -e 's/^[[:alnum:]]*\.//' <<< $DOMAIN)
read -r -p "Enter VPN server local IP address: [192.168.20.1] " IP
[[ -z $IP ]] && IP=192.168.20.1
while ! check_ipprivate "$IP"; do
    echo -e "${RED}Please enter a class C private IP address."
    echo -e "You can use an IP address within the range ${BRED}192.168.0.0 to 192.168.255.255${RED}."
    echo -e "${DECOLOR}"
    read -r -p "Enter VPN server local IP address: [192.168.20.1] " IP
    [[ -z $IP ]] && IP=192.168.20.1
done
NETWORK="$(sed -e 's/[[:digit:]]*$/0/' <<< "$IP")"
NETMASK="255.255.255.0"
echo -e "Netmask is set to $NETMASK."

find_mainif

if [[ -z $FW ]]; then
    [[ "$(os)" == "ubuntu" ]] && firewall_cfg_ufw
    [[ "$(os)" == "centos" ]] && firewall_cfg_firewalld
    [[ "$(os)" == "fedora" ]] && firewall_cfg_firewalld
    [[ "$(os)" == "almalinux" ]] && firewall_cfg_iptables
else
    firewall_cfg_"$FW"
fi

echo -e "Creating certificate directories..."
mkdir -p $keys_dir/{cacerts,private,public}

echo -e "Generating keys and certificates..."
gen_ca
gen_server_crt
gen_user_crt

echo -e "Configuring ocserv..."
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
echo -e "Restarting ocserv service..."
sed -i 's/^\s*server-cert\s*=\s*.*/#&/g' $OCCONF
sed -i 's/^\s*server-key\s*=\s*.*/#&/g' $OCCONF
sed -i 's/^\s*ca-cert\s*=\s*.*/#&/g' $OCCONF
cat <<- EOF >> $OCCONF
    server-cert = $keys_dir/public/server.crt
    server-key = $keys_dir/private/server.key
    ca-cert = $keys_dir/cacerts/ca.crt
EOF
systemctl enable ocserv
systemctl restart ocserv && echo -e "${GREEN}\n\
Successfully installed and configured \"ocserv\".\n
Use ${BGREEN}\"ocpasswd\"${GREEN} command to manage users:\n
${YELLOW}Create:
ocpasswd <username>\n\n\
Delete:
ocpasswd -d <username>\n${DECOLOR}"