function os {
DISTRO=$(cat /etc/os-release | grep -e '^ID=' \
| cut -d = -f 2 | sed -e 's/[[:punct:]]//g' \
| tr [:upper:] [:lower:])
echo $DISTRO
}

function checkuser {
[[ $UID == "0" ]] || { echo "You are not root."; exit 1; }
}