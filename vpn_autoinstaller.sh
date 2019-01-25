#!/bin/bash

###Prepare system

#Ipsec variables
IPSec=0         #IPSec 1 Start IP Subnet
i=4  			#variable for configs IPs increase

#Openvpn variables 
TCP=3   # tcp openvpn
UDP=2   # udp openvpn
IPT=0   # iptables



AptStatus=1             # apt-get update                                -   System update
CertStatus=1            # apt-get install -y $CertPack                  -   openvpn + easyrsa(!debian7) installation
AptIpsecStatus=1        # apt-get install                               -   Strongswan+ Strongswan plugins install
OpenVpnStatus=1         # ps aufx | grep openvpn                        -   Openvpn status (running/not running)
IpsecStatus=1           # ps aufx | grep ipsec                          -   Ipsec status (running/not running)
DpkgStatus=1            # apt-get update                                -   dpkg status check                

#clean configs before install
rm -rf /etc/ipsec.conf
rm -rf /etc/ipsec.secrets
cat /dev/null > /etc/rc.local

#flush iptables rules
iptables -t nat -F
iptables -F

#private network
NETWORKS="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"

###Path for easy-rsa certificates
CertPathD9=/usr/share/easy-rsa/
CertPathD8=/usr/share/easy-rsa/
CertPathD7=/usr/share/doc/openvpn/examples/easy-rsa/2.0/
CertPathU16=/usr/share/easy-rsa/
CertPathU14=/usr/share/easy-rsa/

###Packets for certificates
CertPackD9="easy-rsa"
CertPackD8="easy-rsa"
CertPackD7="openvpn"
CertPackU16="easy-rsa"
CertPackU14="easy-rsa"

###Packets for IPsec (strongswan)
IpsecPackD9="apt-get -y install strongswan libcharon-extra-plugins"
IpsecPackD8="apt-get -y install strongswan libcharon-extra-plugins"
IpsecPackD7="apt-get -y -t wheezy-backports install strongswan libcharon-extra-plugins"
IpsecPackU16="apt-get -y install strongswan strongswan-plugin-xauth-generic"
IpsecPackU14="apt-get -y install strongswan strongswan-plugin-xauth-generic"

### OpenVpn radius plugin
RadiusPluginD9="/usr/lib/openvpn/openvpn-plugin-auth-pam.so"
RadiusPluginD8="/usr/lib/openvpn/openvpn-plugin-auth-pam.so"
RadiusPluginD7="/usr/lib/openvpn/openvpn-auth-pam.so"
RadiusPluginU16="/usr/lib/openvpn/openvpn-plugin-auth-pam.so"
RadiusPluginU14="/usr/lib/openvpn/openvpn-plugin-auth-pam.so"

### Debian7 problems fixing
PreAptD7="apt-get -y install debian-keyring debian-archive-keyring"
PreAptOther="echo please wait!"

function getOS {
if (cat /etc/issue | grep Debian | grep 9 &> /dev/null)
	then
	    cat /dev/null > /etc/apt/sources.list
        cat >> /etc/apt/sources.list <<EOF
        deb http://http.us.debian.org/debian/ stretch main
        deb-src http://http.us.debian.org/debian/ stretch main

        deb http://security.debian.org/debian-security stretch/updates main
        deb-src http://security.debian.org/debian-security stretch/updates main

        deb http://http.us.debian.org/debian/ stretch-updates main
        deb-src http://http.us.debian.org/debian/ stretch-updates main
EOF
	
	    OS=Debian9
	    CertPath=$CertPathD9
	    CertPack=$CertPackD9
	    IpsecPack=$IpsecPackD9
	    RadiusPlugin=$RadiusPluginD9
	    PreApt=$PreAptOther
	    
	  	MAIN

elif (cat /etc/issue | grep Debian | grep 8 &> /dev/null)
	then
	    OS=Debian8
	    CertPath=$CertPathD8
	    CertPack=$CertPackD8
	    IpsecPack=$IpsecPackD8
	    RadiusPlugin=$RadiusPluginD8
	    PreApt=$PreAptOther
	    
		MAIN

elif (cat /etc/issue | grep Debian | grep 7 &> /dev/null)
	then
	    OS=Debian7
	    CertPath=$CertPathD7
	    CertPack=$CertPackD7
	    IpsecPack=$IpsecPackD7
	    RadiusPlugin=$RadiusPluginD7
	    PreApt=$PreAptD7
	    
	    echo "deb http://ftp.debian.org/debian wheezy-backports main" > /etc/apt/sources.list.d/wheezy-backports.list
	    
		MAIN

elif (cat /etc/issue | grep Ubuntu | grep 14 &> /dev/null)
	then
	    cat /dev/null > /etc/apt/sources.list
        cat >> /etc/apt/sources.list <<EOF
        deb http://archive.ubuntu.com/ubuntu/ trusty main restricted
        deb-src http://archive.ubuntu.com/ubuntu/ trusty main restricted

        deb http://archive.ubuntu.com/ubuntu/ trusty-updates main restricted
        deb-src http://archive.ubuntu.com/ubuntu/ trusty-updates main restricted

        deb http://archive.ubuntu.com/ubuntu/ trusty universe
        deb-src http://archive.ubuntu.com/ubuntu/ trusty universe
        deb http://archive.ubuntu.com/ubuntu/ trusty-updates universe
        deb-src http://archive.ubuntu.com/ubuntu/ trusty-updates universe

        deb http://archive.ubuntu.com/ubuntu/ trusty multiverse
        deb-src http://archive.ubuntu.com/ubuntu/ trusty multiverse
        deb http://archive.ubuntu.com/ubuntu/ trusty-updates multiverse
        deb-src http://archive.ubuntu.com/ubuntu/ trusty-updates multiverse

        deb http://archive.ubuntu.com/ubuntu/ trusty-backports main restricted universe multiverse
        deb-src http://archive.ubuntu.com/ubuntu/ trusty-backports main restricted universe multiverse

        deb http://security.ubuntu.com/ubuntu trusty-security main restricted
        deb-src http://security.ubuntu.com/ubuntu trusty-security main restricted
        deb http://security.ubuntu.com/ubuntu trusty-security universe
        deb-src http://security.ubuntu.com/ubuntu trusty-security universe
        deb http://security.ubuntu.com/ubuntu trusty-security multiverse
        deb-src http://security.ubuntu.com/ubuntu trusty-security multiverse
EOF

	    OS=Ubuntu14
	    CertPath=$CertPathU14
	    CertPack=$CertPackU14
	    IpsecPack=$IpsecPackU14
	    RadiusPlugin=$RadiusPluginU14
	    PreApt=$PreAptOther
	    
		MAIN

elif (cat /etc/issue | grep Ubuntu | grep 16 &> /dev/null)
	then
	    OS=Ubuntu16
	    CertPath=$CertPathU16
	    CertPack=$CertPackU16
	    IpsecPack=$IpsecPackU16
	    RadiusPlugin=$RadiusPluginU16
	    PreApt=$PreAptOther
	    
		MAIN
fi
}

function MAIN {
echo $OS detected!


###Updating system

$PreApt
apt-get upgrade
apt-get update || AptStatus=0

###Packets install
apt-get install -y curl pwgen python-pip python-dev openssl build-essential autoconf libtool pkg-config ppp xl2tpd make grepcidr 
    
###Certificates generating
apt-get install -y $CertPack || CertStatus=0

mkdir -p $CertPath/keys
egrep -lRZ 'export KEY_ORG="Fort-Funston"' $CertPath/vars | xargs -0 -l sed -i -e 's|export KEY_ORG="Fort-Funston"|export KEY_ORG="Snowd"|g'
egrep -lRZ 'export KEY_EMAIL="me@myhost.mydomain"' $CertPath/vars | xargs -0 -l sed -i -e 's|export KEY_EMAIL="me@myhost.mydomain"|export KEY_EMAIL="info@snowd.com"|g'
egrep -lRZ 'export KEY_OU="MyOrganizationalUnit"' $CertPath/vars | xargs -0 -l sed -i -e 's|export KEY_OU="MyOrganizationalUnit"|export KEY_OU="Snowd"|g'
egrep -lRZ 'export KEY_NAME="EasyRSA"' $CertPath/vars | xargs -0 -l sed -i -e 's|export KEY_NAME="EasyRSA"|export KEY_NAME="server"|g'
egrep -lRZ 'export KEY_SIZE=1024' $CertPath/vars | xargs -0 -l sed -i -e 's|export KEY_SIZE=1024|export KEY_SIZE=2048|g'
cp $CertPath/openssl-1.0.0.cnf $CertPath/openssl.cnf

cd  $CertPath ; source vars ; ./clean-all ; ./build-ca --batch ; ./build-key-server --batch server ; ./build-dh --batch 

#copy certs
mkdir -p /etc/openvpn
cp $CertPath/keys/ca.crt      /etc/openvpn/
cp $CertPath/keys/dh2048.pem  /etc/openvpn/
cp $CertPath/keys/server.crt  /etc/openvpn/
cp $CertPath/keys/server.key  /etc/openvpn/
cp $CertPath/keys/ca.crt      /etc/openvpn/


###IPSEC block

#Install Strongswan and plugins
DEBIAN_FRONTEND=noninteractive $IpsecPack || AptIpsecStatus=0
   
#name of the main interface
Int=$(ls /sys/class/net | grep -E "ens|eth0")

# Pool of servers IPs
Server_IPs=$( ip a | grep "$Int" | grep -v "mtu"| grep -v "default" |   awk '{print $2}' | awk -F '/' '{print $1}')

cat /dev/null > /etc/ipsec.conf
cat /dev/null > /etc/ipsec.secrets
Secret=$(pwgen 10 1)

function ipsecConfig {
cat >> /etc/ipsec.conf <<EOF
conn $1_v1
    authby=secret
    rekeymargin=3m
    keyingtries=%forever
    keyexchange=ikev1
    leftfirewall=yes
    rekey=no
    left=$1
    leftsubnet=0.0.0.0/0
    leftauth=psk
    rightsubnet=10.0.$2.0/24
    rightsourceip=10.0.$2.2/24
    rightdns=8.8.8.8
    right=%any
    rightauth=psk
    rightauth2=xauth
    dpdaction=hold
    ikelifetime=12h
    dpddelay=12h
    dpdtimeout=5s
    auto=add

EOF

echo   ''$1' %any : PSK '$3''   >>  /etc/ipsec.secrets
}

for IP in $Server_IPs 
        do
                grepcidr "$NETWORKS" <( echo "$IP" ) > /dev/null  || ipsecConfig $IP $IPSec $Secret
                IPSec=$(($IPSec+$i))
        done

#additional ipsec.conf string
sed -i '1iconfig setup\' 	 /etc/ipsec.conf
sed -i '2i\    uniqueids=never\' /etc/ipsec.conf

#build ta.key
apt-get install -y openvpn
openvpn --genkey --secret /etc/openvpn/ta.key

function openVpnConfig {

#create TCP config
touch /etc/openvpn/"$1"_server_tcp.conf
cat /dev/null > /etc/openvpn/"$1"_server_tcp.conf

cat > /etc/openvpn/"$1"_server_tcp.conf <<EOF
local $1
port 443
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.0.$2.0 255.255.255.0
plugin $5 login
username-as-common-name
client-to-client
keepalive 10 120
client-cert-not-required
cipher AES-256-CBC
auth MD5
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
mute 20
tcp-nodelay
duplicate-cn
tls-auth ta.key 0
fragment 0
mssfix 0
sndbuf 0
rcvbuf 0
push "sndbuf 393216"
push "rcvbuf 393216"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
EOF

#create UDP config
touch /etc/openvpn/"$1"_server_udp.conf
cat /dev/null > /etc/openvpn/"$1"_server_udp.conf

cat > /etc/openvpn/"$1"_server_udp.conf <<EOF
local $1
port  1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
server 10.0.$3.0 255.255.255.0
plugin $5 login
username-as-common-name
client-to-client
keepalive 10 120
client-cert-not-required
cipher AES-256-CBC
auth MD5
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
mute 20
tcp-nodelay
duplicate-cn
tls-auth ta.key 0
fragment 0
mssfix 0
sndbuf 0
rcvbuf 0
push "sndbuf 393216"
push "rcvbuf 393216"
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
EOF

### iptables rules
iptables -t nat -A POSTROUTING -s 10.0.$4.0/22 -j SNAT --to-source $1

### /etc/rc.local change
echo 'iptables -t nat -A POSTROUTING -s 10.0.'$4'.0/22 -j SNAT --to-source '$1''  >> /etc/rc.local
}

for IP in $Server_IPs
        do
                grepcidr "$NETWORKS" <( echo "$IP" ) > /dev/null  || openVpnConfig $IP $TCP $UDP $IPT $RadiusPlugin
                TCP=$(($TCP+$i))
                TCP=$(($UDP+$i))
                IPT=$(($IPT+$i))
        done

# finish change /etc/rc.local
echo "dpkg --configure -a  &> /root/test.log" >> /etc/rc.local
echo "exit 0" >> /etc/rc.local
sed -i '1s|^|#!/bin/bash\n|' /etc/rc.local

chmod +x /etc/rc.local

# sysctl config
echo 1 > /proc/sys/net/ipv4/ip_forward
egrep -lRZ '#net.ipv4.ip_forward=1' /etc/sysctl.conf | xargs -0 -l sed -i -e 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|g' 
egrep -lRZ '#AUTOSTART="all"' /etc/default/openvpn | xargs -0 -l sed -i -e 's|#AUTOSTART="all"|AUTOSTART="all"|g' 

#restart  Services
systemctl daemon-reload      
/etc/init.d/openvpn restart  
update-rc.d openvpn defaults 
service strongswan restart || service ipsec restart || ipsec restart   ## Ipsec restart for different OS


### Check Status of services
ps aufx | grep -v "grep" | grep openvpn > /dev/null || OpenVpnStatus=0
ps aufx | grep -v "grep" | grep ipsec > /dev/null || IpsecStatus=0



#Function MAIN Finished
}

getOS

          
#### Dpkg Fix ubuntu14
/etc/rc.local
/bin/sed -i '/dpkg/d' /etc/rc.local  #deleting dpkg fix raw in rc.local

apt-get update  || DpkgStatus=0       #Check for fixing dpkg errors (Mostly with Ubuntu 14)



#### Finish. User and client-config creation.

Int=$(ls /sys/class/net | grep -E "ens|eth0")

MainIP=$(ip a | grep "$Int" | grep global | grep -v "$Int": | awk '{print $2}' | awk -F '/' '{print $1}')


mkdir -p /etc/openvpn/client-configs
rm -rf /etc/openvpn/client-configs/*

function config {
touch /etc/openvpn/client-configs/$1.txt
cat > /etc/openvpn/client-configs/$1.txt <<EOF
client
auth-user-pass
dev tun
resolv-retry 4
nobind
persist-key
comp-lzo
verb 4
cipher AES-256-CBC
auth MD5
dhcp-option DNS 8.8.8.8
dhcp-option DNS 8.8.4.4
key-direction 1

remote $1 443 tcp
remote $1 1194 udp

<ca>
</ca>
<tls-auth>
</tls-auth>
EOF

sed -i -e '/<ca>/r /etc/openvpn/ca.crt' /etc/openvpn/client-configs/$1.txt  
sed -i -e '/<tls-auth>/r /etc/openvpn/ta.key' /etc/openvpn/client-configs/$1.txt    
    
}

for IP in $Server_IPs
	do
                grepcidr "$NETWORKS" <( echo "$IP" ) > /dev/null  || config  $IP
        done


###Users creation
User=$(pwgen 10 1)
Password=$(pwgen 10 1)

echo  ""$User" : XAUTH  \"$Password\" " >> /etc/ipsec.secrets

useradd --shell=/bin/nologin -p $Password $User
echo -e "$Password\n$Password" | (passwd $User) &> /dev/null
 

service strongswan restart || service ipsec restart || ipsec restart   ## Ipsec restart for different OS


## Api Answer
curl -d "id=$1&login=$User&pw=$Password&secret=$Secret&AptStatus=$AptStatus&CertStatus=$CertStatus&AptIpsecStatus=$AptIpsecStatus&OpenVpnStatus=$OpenVpnStatus&IpsecStatus=$IpsecStatus&DpkgStatus=$DpkgStatus" "https://snowd.com/api/autoinstall_response.php"

rm -- "$0"    #Installer deleting
