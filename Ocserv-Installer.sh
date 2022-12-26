#!/bin/bash
# Secure OpenConnect server installer for Ubuntu 18.04 or higher.
# https://github.com/B-andi-T
RED='\e[0;31m'
YELLOW='\e[0;33m'
GREEN='\e[0;32m'
BOLDGREEN="\e[1;32m"
CYAN='\e[0;36m'
EC='\e[0m'
DEFUSER=user
PORT=443
PDNS=8.8.8.8
SDNS=4.2.2.4
ocservConfig=/etc/ocserv/ocserv.conf
NET_INTER=$(ip r | head -1 | cut -d" " -f5)
serverlist=$(stat -c %n /lib/systemd/system/ocserv*.service | wc -l)
serverlist_names=$(for file in /lib/systemd/system/ocserv*.service; do basename "$file"; done | awk -F. '{print $1}')
findCert=$(find /etc/letsencrypt/live/ -type d -name $DOMAIN)

clear

function isRoot() {
  if ! [ $(id -u) -eq 0 ]; then
    echo "You need to run this script as root"
    exit 1
  fi
}

function checkOS() {
  # Check OS version
  if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    testvercomp $VERSION_ID "18.04" "<"
    echo "OS : $ID"
    echo "OS Version : $VERSION"
    if [[ $ID != "ubuntu" ]]; then
      echo -e "Your OS does not supported for using this script. Only Ubuntu 18.04 or higher is supported."
      exit
    fi
    if [[ $VERID -eq 0 ]]; then
      OS=$ID
      # On Ubuntu systems
      echo -e "Your version of Ubuntu ($VERSION_ID) is not supported by this script. Please upgrade your Ubuntu version to 18.04 or higher."
      exit
    fi
  else
    echo -e "Your OS does not supported for using this script. Only Ubuntu 18.04 or higher is supported."
    exit
  fi
  Questions

}

vercomp() {
  if [[ $1 == $2 ]]; then
    return 0
  fi
  local IFS=.
  local i ver1=($1) ver2=($2)
  # fill empty fields in ver1 with zeros
  for ((i = ${#ver1[@]}; i < ${#ver2[@]}; i++)); do
    ver1[i]=0
  done
  for ((i = 0; i < ${#ver1[@]}; i++)); do
    if [[ -z ${ver2[i]} ]]; then
      # fill empty fields in ver2 with zeros
      ver2[i]=0
    fi
    if ((10#${ver1[i]} > 10#${ver2[i]})); then
      return 1
    fi
    if ((10#${ver1[i]} < 10#${ver2[i]})); then
      return 2
    fi
  done
  return 0
}

testvercomp() {
  vercomp $1 $2
  case $? in
  0) op='=' ;;
  1) op='>' ;;
  2) op='<' ;;
  esac
  if [[ $op != $3 ]]; then
    VERID=1
  else
    VERID=0
  fi
}

# OCServ Questions before install
function Questions() {
  echo -e "\n                OOOOO   CCCCC   SSSSS  EEEEEEE RRRRRR  VV     VV\n               OO   OO CC      SS      EE      RR   RR VV     VV\n               OO   OO CC       SSSSS  EEEEE   RRRRRR   VV   VV \n               OO   OO CC           SS EE      RR  RR    VV VV  \n                OOOO0   CCCCC   SSSSS  EEEEEEE RR   RR    VVV   "
  echo "######################################################################################"
  echo "#Script Name	:  Secure OpenConnect+LetsEncrypt server installer for Ubuntu 18.04 and later."
  echo "#Description	:  With this script you can start your Openconnect+LetsEncrypt server in less than a minute"
  echo "#Author         :  B-andi-T"
  echo "#Github         :  https://github.com/B-andi-T"
  echo "######################################################################################"
  echo -e "\n${CYAN}Welcome to Openconnect+LetsEncrypt Installer for ubuntu 18.04 and later${EC}\n"
  echo "###/N/###/O/###/T/###/E/###"
  echo -e "\nPlease note
   * This script has been tested on ${GREEN}Ubuntu 18.04, 20.04 and 22.04.${EC}"
  echo -e "   * you need a ${RED}domain${EC} to set up the server. If you don't have one, buy one first before using this script.\n"
  echo "###\N\###\O\###\T\###\E\###"
  echo -ne "\nNow if all the prerequisites are ready, you need to answer a few simple questions:\n"
  echo -e "${RED}**Please answer the all questions correctly**${EC}"
  # Questions
  # Detect Network Interface
  read -rp "Network Interface (leave it unchanged unless you know what you are doing): " -e -i "$NET_INTER"
  # Email
  if email_validator $email; then
    EMAIL=$email
  fi
  # Username
  echo -n "Please enter your username (default is 'user') : "
  read userName
  if [[ -n "$userName" ]]; then
    DEFUSER=$userName
  fi
  # Password
  if pass_validator $password; then
    PASS=$password
  fi
  # Port
  newPortnumber $newPort
  PORT=$newPort
  # Max Same Client
  until [[ $maxSameClient =~ ^[0-9]+$ ]]; do
    read -rp "The number of devices that can be used by a user at the same time (Default is 2)(0 is unlimited): " -e -i 2 maxSameClient
  done
  # Primary DNS
  while true; do
    echo -n "Primary DNS (default is 8.8.8.8): "
    read primaryDns
    if [[ -z $primaryDns ]]; then
      primaryDns=$PDNS
      echo -e "${YELLOW}Primary DNS will be set to $primaryDns${EC}"
      break
    else
      if valid_ip $primaryDns; then
        stat='will be used as your Primary DNS'
        echo -e "$primaryDns" "${GREEN}$stat${EC}"
        break
      else
        stat='is not a valid IP address.'
        echo -e "$primaryDns" "${RED}$stat${EC}"
      fi
    fi
  done
  # Secondary DNS
  while true; do
    echo -n "Secondary DNS (Optional): "
    read secDns
    if [[ -z "$secDns" ]]; then
      secDns=$SDNS
      echo -e "${YELLOW}Secondary DNS will be set to $secDns${EC}"
      break
    else
      if valid_ip $secDns; then
        stat='will be used as your Secondary DNS'
        echo -e "$secDns" "${GREEN}$stat${EC}"
        SDNS=$secDns
        break
      else
        stat='is not a valid IP address.'
        echo -e "$secDns" "${RED}$stat${EC}"
      fi
    fi
  done
  # Check Apache
  echo "/./././././././././././././././././././././././././"
  echo -e "Checking if ${CYAN}Apache${EC} is installed on this machine..."
  sleep 2
  if command -v apache2 >/dev/null; then
    if (systemctl -q is-active apache2); then
      echo -e "${RED}ATTENTION!${EC}"
      echo -e "It seems ${CYAN}Apache${EC} is already installed on your server"
      echo -e "Since LetsEncrypt needs port 80 to obtain the certificate and Apache is already using port 80, you can obtain the certificate through Apache.
  If you want the certificate to be created with 'Standalone Plugin', you can choose 'n' so that Apache will be stoped during installation and re-started after the script is finished processing."
      apaChe
    else
      echo -e "It seems ${CYAN}Apache${EC} is installed on this machine but it's inactive. If you want to use apache for obtain the Certificate, you can activate it."
      local CONTINUE=""
      until [[ $CONTINUE =~ (y|n) ]]; do
        read -rp "Do you want to enable apache2 service? [y/n]:" -e CONTINUE
      done
      if [[ $CONTINUE == y ]]; then
        systemctl start apache2
        apaChe
      else
        if newDomain $domainInput; then
          DOMAIN=$domainInput
        fi
      fi
    fi
  else
    echo -e "${CYAN}Apache Not Found${EC}"
    echo "/./././././././././././././././././././././././././"
  fi
  # Check Nginx
  echo -e "Checking if ${CYAN}Nginx${EC} is installed on this machine..."
  sleep 2
  if command -v nginx >/dev/null; then
    if (systemctl -q is-active nginx); then
      echo -e "${RED}ATTENTION!${EC}"
      echo -e "It seems ${CYAN}Nginx${EC} is already installed on your server"
      echo -e "Since LetsEncrypt needs port 80 to obtain the certificate and Nginx is already using port 80, you can obtain the certificate through Nginx.
  If you want the certificate to be created with 'Standalone Plugin', you can choose 'n' so that Nginx will be stoped during installation and re-started after the script is finished processing."
      nginX
    else
      echo -e "It seems ${CYAN}Nginx${EC} is installed on this machine but it's inactive. If you want to use Nginx for obtain the Certificate, you can activate it."
      local CONTINUE=""
      until [[ $CONTINUE =~ (y|n) ]]; do
        read -rp "Do you want to enable Nginx service? [y/n]:" -e CONTINUE
      done
      if [[ $CONTINUE == y ]]; then
        systemctl start nginx
        nginX
      else
        if newDomain $domainInput; then
          DOMAIN=$domainInput
        fi
      fi
    fi
  else
    echo -e "${CYAN}Nginx Not Found${EC}"
    echo "/./././././././././././././././././././././././././"
  fi
  if ! command -v apache2 >/dev/null && ! command -v nginx >/dev/null; then
    if newDomain $domainInput; then
      DOMAIN=$domainInput
    fi
  fi
  # End of questions and confirmation to continue
  echo -e "\nAll questions answered. Now it's time to install. Do you wish to continue?"
  select yn in "Yes" "No"; do
    case $yn in
    Yes)
      OCSERV_INSTALL
      break
      ;;
    No) exit ;;
    esac
  done
}

function OCSERV_INSTALL() {

  # Installation and configuration
  # OS UPDATE & UPGRADE
  echo -e "${GREEN}Running apt update...${EC} "
  spin &
  pid=$!
  apt-get update &>/dev/null
  echo -e "\nDONE\n"
  kill $pid >/dev/null 2>&1
  echo -e "${GREEN}Running apt upgrade...${EC} "
  apt-get upgrade -y
  echo -e "${GREEN}DONE${EC}"
  # Install OCServ and Certbot
  echo -e "${GREEN}Installing OCServ...${EC}"
  apt-get install -y ocserv
  echo -e "${GREEN}DONE${EC}"
  echo -e "${GREEN}Installing Certbot...${EC}"
  apt-get install -y certbot
  echo -e "${GREEN}DONE${EC}"

  # Getting TLS certificate from Let's Encrypt
  echo -e "${GREEN}Getting TLS certificate from LetsEncrypt...${EC}"
  # Using standAlone plugin if Apache and Nginx are not active
  if [[ $(ps -acx | grep nginx | wc -l) == 0 ]] && [[ $(ps -acx | grep apache | wc -l) == 0 ]]; then
    if [ $findCert ]; then
      echo "1" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
    else
      echo "n" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
    fi
    sed -i "s/server-cert = \/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem/" $ocservConfig
    sed -i "s/server-key = \/etc\/ssl\/private\/ssl-cert-snakeoil.key/server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem/" $ocservConfig
  fi
  # Use Webroot plugin for certificate (Apache)
  if [[ $USE_APACHE == y ]]; then
    if [[ $HAVE_DOMAIN == y ]]; then
      if [[ $CERT_EXIST == n ]]; then
        SAVAILABLE=$(grep "ServerName $DOMAIN" "/etc/apache2/sites-available/$DOMAIN.conf")
        if ! [[ -z $SAVAILABLE ]] && [[ -d /var/www/$DOMAIN ]]; then
          a2ensite $DOMAIN
          systemctl reload apache2
          echo "n" | certbot certonly --webroot --agree-tos --email ${EMAIL} -d ${DOMAIN} -w /var/www/$DOMAIN
          sed -i "s/server-cert = \/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem/" $ocservConfig
          sed -i "s/server-key = \/etc\/ssl\/private\/ssl-cert-snakeoil.key/server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem/" $ocservConfig
        else
          touch /etc/apache2/sites-available/$DOMAIN.conf
          echo "<VirtualHost *:80>        
        ServerName $DOMAIN
        DocumentRoot /var/www/ocserv
</VirtualHost>" >>/etc/apache2/sites-available/$DOMAIN.conf
          mkdir /var/www/ocserv
          chown www-data:www-data /var/www/ocserv -R
          a2ensite $DOMAIN
          systemctl reload apache2
          certbot certonly --webroot --agree-tos --email ${EMAIL} -d ${DOMAIN} -w /var/www/ocserv
        fi
      else
        sed -i "/server-cert =/c\server-cert = ${CERTPATH//\//\\/}" $ocservConfig
        sed -i "/server-key =/c\server-key = ${KEYPATH//\//\\/}" $ocservConfig
      fi
    else
      touch /etc/apache2/sites-available/$DOMAIN.conf
      echo "<VirtualHost *:80>        
        ServerName $DOMAIN
        DocumentRoot /var/www/ocserv
</VirtualHost>" >>/etc/apache2/sites-available/$DOMAIN.conf
      mkdir /var/www/ocserv
      chown www-data:www-data /var/www/ocserv -R
      a2ensite $DOMAIN
      systemctl reload apache2
      certbot certonly --webroot --agree-tos --email ${EMAIL} -d ${DOMAIN} -w /var/www/ocserv
      sed -i "s/server-cert = \/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem/" $ocservConfig
      sed -i "s/server-key = \/etc\/ssl\/private\/ssl-cert-snakeoil.key/server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem/" $ocservConfig
    fi
  else
    if (systemctl is-active --quiet apache2); then
      echo -e "${GREEN}Stopping the Apache service...${EC}"
      systemctl stop apache2
      sleep 2
      if [ $findCert ]; then
        echo "1" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
      else
        echo "n" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
      fi
      sed -i "s/server-cert = \/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem/" $ocservConfig
      sed -i "s/server-key = \/etc\/ssl\/private\/ssl-cert-snakeoil.key/server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem/" $ocservConfig
    fi
  fi

  # Use Webroot plugin for certificate (Nginx)
  if [[ $USE_NGINX == y ]]; then
    if [[ $HAVE_DOMAIN == y ]]; then
      if [[ $CERT_EXIST == n ]]; then
        SAVAILABLE=$(grep "server_name $DOMAIN" "/etc/nginx/conf.d/$DOMAIN.conf")
        if ! [[ -z $SAVAILABLE ]] && [[ -d /var/www/$DOMAIN ]]; then
          echo "n" | certbot certonly --webroot --agree-tos --email ${EMAIL} -d ${DOMAIN} -w /var/www/$DOMAIN
          sed -i "s/server-cert = \/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem/" $ocservConfig
          sed -i "s/server-key = \/etc\/ssl\/private\/ssl-cert-snakeoil.key/server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem/" $ocservConfig
          systemctl reload nginx
        else
          touch /etc/nginx/conf.d/$DOMAIN.conf
          echo "server {
      listen 80;
      server_name $DOMAIN;

      root /var/www/ocserv/;

      location ~ /.well-known/acme-challenge {
        allow all;
      }
}" >>/etc/nginx/conf.d/$DOMAIN.conf
          mkdir -p /var/www/ocserv
          chown www-data:www-data /var/www/ocserv -R
          systemctl reload nginx
          certbot certonly --webroot --agree-tos --email ${EMAIL} -d ${DOMAIN} -w /var/www/ocserv
        fi
      else
        sed -i "/server-cert =/c\server-cert = ${CERTPATH//\//\\/}" $ocservConfig
        sed -i "/server-key =/c\server-key = ${KEYPATH//\//\\/}" $ocservConfig
      fi
    else
      touch /etc/nginx/conf.d/$DOMAIN.conf
      echo "server {
      listen 80;
      server_name $DOMAIN;

      root /var/www/ocserv/;

      location ~ /.well-known/acme-challenge {
        allow all;
      }
}" >>/etc/nginx/conf.d/$DOMAIN.conf
      mkdir -p /var/www/ocserv
      chown www-data:www-data /var/www/ocserv -R
      systemctl reload nginx
      certbot certonly --webroot --agree-tos --email ${EMAIL} -d ${DOMAIN} -w /var/www/ocserv
      sed -i "s/server-cert = \/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem/" $ocservConfig
      sed -i "s/server-key = \/etc\/ssl\/private\/ssl-cert-snakeoil.key/server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem/" $ocservConfig
    fi
  else
    if (systemctl is-active --quiet nginx); then
      echo -e "${GREEN}Stopping the Nginx service...${EC}"
      systemctl stop nginx
      sleep 2
      if [ $findCert ]; then
        echo "1" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
      else
        echo "n" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
      fi
      sed -i "s/server-cert = \/etc\/ssl\/certs\/ssl-cert-snakeoil.pem/server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem/" $ocservConfig
      sed -i "s/server-key = \/etc\/ssl\/private\/ssl-cert-snakeoil.key/server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem/" $ocservConfig
    fi
  fi

  # OCServ Configuration
  sed -i 's/auth = "pam\[gid-min=1000]"/auth = "plain\[passwd=\/etc\/ocserv\/ocpasswd]"/' $ocservConfig
  sed -i "s/tcp-port = 443/tcp-port = $PORT/" $ocservConfig
  sed -i "s/udp-port = 443/#udp-port = $PORT/" $ocservConfig
  sed -i "s/max-same-clients = 2/max-same-clients = ${maxSameClient}/" $ocservConfig
  sed -i 's/keepalive = 300/keepalive = 30/' $ocservConfig
  sed -i 's/try-mtu-discovery = false/try-mtu-discovery = true/' $ocservConfig
  sed -i "s/default-domain = example.com/default-domain = $DOMAIN/" $ocservConfig
  sed -i 's/max-clients = 128/max-clients = 0/' $ocservConfig
  sed -i 's/ipv4-network = 192.168.1.0/ipv4-network = 10.10.10.0/' $ocservConfig
  sed -i 's/#ipv6-network = fda9:4efe:7e3b:03ea::\/48/ipv6-network = fda9:4efe:7e3b:03ea::\/48/' $ocservConfig
  sed -i 's/#ipv6-subnet-prefix = 64/ipv6-subnet-prefix = 64/' $ocservConfig
  sed -i 's/#tunnel-all-dns = true/tunnel-all-dns = true/' $ocservConfig
  sed -i "s/dns = 8.8.8.8/dns = $PDNS/" $ocservConfig
  sed -i "s/dns = 1.1.1.1/dns = $SDNS/" $ocservConfig
  sed -i 's/route = 10.0.0.0\/8/#route = 10.0.0.0\/8/' $ocservConfig
  sed -i 's/route = 172.16.0.0\/12/#route = 172.16.0.0\/12/' $ocservConfig
  sed -i 's/route = 192.168.0.0\/16/#route = 192.168.0.0\/16/' $ocservConfig
  echo -e "\n${RED}Configuration Completed${EC}\n"

  #  Creating Password for user
  echo -e "$PASS\n$PASS" | ocpasswd -c /etc/ocserv/ocpasswd $DEFUSER
  wait
  #  Enable ipv4 IP forward
  echo -e "\n${GREEN}Enabling ipv4 IP forward...${EC}\n"
  echo "net.ipv4.ip_forward = 1" | tee /etc/sysctl.d/60-custom.conf
  echo "DONE"
  # Enable TCP BBR
  echo -e "\n${GREEN}Enabling TCP BBR algorithm...${EC}\n"
  echo "net.core.default_qdisc=fq" | tee -a /etc/sysctl.d/60-custom.conf
  echo "net.ipv4.tcp_congestion_control=bbr" | tee -a /etc/sysctl.d/60-custom.conf
  echo "DONE"
  echo -e "\n${GREEN}Apply the changes...${EC}\n"
  sysctl -p /etc/sysctl.d/60-custom.conf
  echo "DONE"
  # UFW
  apt-get install -y ufw &>/dev/null
  ufw allow ssh &>/dev/null
  ufw allow 80/tcp &>/dev/null
  ufw allow ${PORT}/tcp &>/dev/null
  ufw allow 80/udp &>/dev/null
  ufw allow ${PORT}/udp &>/dev/null
  echo "y" | ufw enable &>/dev/null
  systemctl restart ocserv

  #  Add NAT Rule
  echo "# NAT table rules OCServ
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s 10.10.10.0/24 -o ${NET_INTER} -j MASQUERADE
COMMIT" >>/etc/ufw/before.rules
  #  Allow Forwading OcServ
  sed -i '/-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT/a # allow forwarding OCServ' /etc/ufw/before.rules
  sed -i '/# allow forwarding OCServ/a -A ufw-before-forward -s 10.10.10.0\/24 -j ACCEPT' /etc/ufw/before.rules
  sed -i '/-A ufw-before-forward -s 10.10.10.0\/24 -j ACCEPT/a -A ufw-before-forward -d 10.10.10.0\/24 -j ACCEPT' /etc/ufw/before.rules
  wait
  systemctl restart ufw
  echo "Waiting 10 seconds for UFW..."
  spin &
  pid=$!
  sleep 10
  kill $pid >/dev/null
  echo -e "\n${GREEN}Display the result:${EC}"
  iptables -t nat -L POSTROUTING

  # Restarting Apache if Apache is active on the server and the user did not want to use Apache to obtain the certificate
  if [[ $USE_APACHE == n ]]; then
    if command -v apache2 >/dev/null; then
      echo -e "${GREEN}Restarting Apache${EC}"
      systemctl start apache2
    fi
  fi
  # Restarting Nginx if Nginx is active on the server and the user did not want to use Nginx to obtain the certificate
  if [[ $USE_NGINX == n ]]; then
    if command -v nginx >/dev/null; then
      echo -e "${GREEN}Restarting Nginx${EC}"
      systemctl start nginx
    fi
  fi

  # Completion of the operation and display the client connection information
  echo -e "${YELLOW}###################################################################${EC}"
  echo -e "Your OpenConnect server ${GREEN}is ready to use.${EC}"
  echo -e "For Clients : \n${YELLOW}OpenConnect for Windows: ${EC}https://github.com/openconnect/openconnect-gui/releases/download/v1.5.3/openconnect-gui-1.5.3-win32.exe"
  echo -e "${YELLOW}Anyconnect for Android: ${EC}https://play.google.com/store/apps/details?id=com.cisco.anyconnect.vpn.android.avf&hl=en&gl=US"
  echo -e "${YELLOW}For Apple devices:${EC}Download AnyConnect from the App Store"
  echo -e "\n${GREEN}Use the following information to connect the client: ${EC}"
  echo -e "Server Address : $DOMAIN:$PORT"
  echo -e "Username : $DEFUSER\nPassword : $PASS"
  echo -e "If you want to add a new user, just run the script again.\n"
  echo -e "${CYAN}There is no need to do anything manually. By running the script again from now, you have a menu where you can make all the settings through it.${EC}"
  echo -e "${YELLOW}###################################################################${EC}"
  echo -e "If you are happy with my script, you can make me happy with a small amount of ${GREEN}donation${EC}."
  echo -e "My ${RED}Tether(USDT) TRC20${EC} Wallet : ${GREEN}TS3ipuQo27mXqxzrehtupgHrMyjKmf7wKz${EC}"
  echo -e "My ${CYAN}Dash${EC} Wallet : ${GREEN}XokprTdUa9B2fXmSZF6ErdrVQWg6MTtebj${EC}"
  echo -e "My ${GREEN}BitcoinCash${EC} Wallet : ${GREEN}qz8uz6k7rwymtlad2rlhlqhxntl6t39s8g96kcumac${EC}"
  echo -e "My LiteCoin Wallet : ${GREEN}ltc1qkw00pa4u4wmhnl807v4grca0qpq2pl0z26hc8k${EC}"
  echo -e "My ${YELLOW}DogeCoin${EC} Wallet : ${GREEN}DToe1gyAvpUhDZFgL1FKYvyT818cFKUskf${EC}"
  echo -e "${RED}Cheers!${EC}"

}

# Remove OCServ
function OCremove() {
  echo "##############################"
  echo -e "${GREEN}Removing OCServ${EC}"
  echo "##############################"
  until [[ $CONTINUE =~ (y|n) ]]; do
    read -rp "Do you want to delete all the users that were created for OCServ? [y/n]: " -e CONTINUE
  done
  echo -e "Just wait a moment..."
  systemctl stop ocserv*.service &>/dev/null
  findPort=$(for file in /etc/ocserv/ocserv*.conf; do grep "tcp-port =" $file; done | awk '{print $3}')
  findNumber=$(for i in $findPort; do ufw status numbered | grep -E $i | awk -F"[][]" '{print $2}'; done | sort -nr | cut -f 2-)
  for i in $findNumber; do yes | ufw delete $i &>/dev/null; done
  if [[ $CONTINUE == "y" ]]; then
    rm -R /etc/ocserv
  fi
  spin &
  pid=$!
  apt purge -y ocserv &>/dev/null
  apt -y autoremove &>/dev/null
  kill $pid &>/dev/null
  rm /lib/systemd/system/ocserv*.service &>/dev/null
  # Remove NAT table rules
  sed -i "/# NAT table rules OCServ*/,+4d" /etc/ufw/before.rules
  sed -i "/# allow forwarding OCServ*/,+2d" /etc/ufw/before.rules
  systemctl restart ufw
  echo "##############################"
  echo -e "${GREEN}DONE${EC}"
  echo -e "${CYAN}The LetsEncrypt is left intact to prevent the deletion of certificates created by you. If you want to remove it, use the following command:${EC}\napt purge certbot"
  echo "##############################"

}

# Main Menu
function mainmenu() {
  source /etc/os-release
  echo "OS : $ID"
  echo "OS Version : $VERSION"
  ocserv -v
  echo -e "\nServices status:"
  if (command -v ocserv &>/dev/null); then
    for file in $serverlist_names; do
      echo "$file : $(systemctl is-active $file)"
    done
  else
    echo -e "There are no active services"
  fi

  echo -ne "
  ${BOLDGREEN}MAIN MENU${EC}
  ${RED}1${EC}) Users Menu
  ${RED}2${EC}) OCServ Menu
  ${RED}3${EC}) LetsEncrypt Menu
  ${RED}4${EC}) Add Multiple OCServ
  ${RED}5${EC}) Remove OCServ 'Use it carefully. Can not be undone (LetsEncrypt will not be removed)'
  ${RED}0${EC}) Exit
  Choose an option:  "
  read -r ans
  case $ans in
  1)
    clear
    UserMenu
    ;;
  2)
    clear
    OCServMenu
    ;;
  3)
    clear
    LetsEncrypt_Menu
    ;;
  4)
    clear
    AddMultipleOC_Question
    ;;
  5)
    clear
    OCremovequestion
    ;;
  0)
    clear
    echo "If you need anything, I'm here!
Bye Bye"
    exit 0
    ;;
  *)
    clear
    echo "$ans is Wrong."
    mainmenu
    ;;
  esac
}

# Add New User
function UserMenu_ADD() {

  echo -n "Please enter a new username:  "
  read userInput
  if ((${#userInput} < 4)); then
    echo -e "${RED}Username is too short, at least 4 characters are required.${EC}" >&2
    UserMenu_ADD
  else
    if [[ -n "$userInput" ]]; then
      NEWUSER=$userInput
    fi
    if grep -w "${NEWUSER}" /etc/ocserv/ocpasswd; then
      echo "User is already exist"
      UserMenu_ADD
    elif pass_validator $passWord; then
      echo -e "$password\n$password" | ocpasswd -c /etc/ocserv/ocpasswd $NEWUSER
      clear
      echo -e "\nThe user '${YELLOW}$NEWUSER${EC}' has been successfully created. "
      UserMenu
    fi
  fi

}

# Revoke an existing user
function UserMenu_Revoke() {
  PS3="Pick a username to remove (0 for back to the menu): "
  LIST=$(awk -F: '{print $1}' "/etc/ocserv/ocpasswd")
  options=($LIST)
  if [[ -z $LIST ]]; then
    echo "No users found."
    UserMenu
  fi
  select menu in "${options[@]}"; do
    echo -e "\nyou picked $menu ($REPLY)"
    if [[ $REPLY == 0 ]]; then
      clear
      UserMenu
    else
      if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
        clear
        echo -e "${RED}Wrong number. User not found.${EC}"
        UserMenu_Revoke
      else
        clear
        ocpasswd -d $menu
        echo -e "The User account "${YELLOW}$menu${EC}" has been successfully deleted. \n"
        UserMenu
      fi
    fi
    break
  done
}

# Change the password for an existing user
function pass_change() {
  PS3="Pick a user to change the password (Enter 0 to Cancel): "
  LIST=$(awk -F: '{print $1}' "/etc/ocserv/ocpasswd")
  options=($LIST)
  if [[ -z $LIST ]]; then
    echo "No users found."
    UserMenu_Modify
  fi
  select menu in "${options[@]}"; do
    echo -e "\nyou picked $menu ($REPLY)"
    if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
      clear
      echo -e "${RED}Wrong number. User not found.${EC}"
      pass_change
    elif [[ $REPLY -eq 0 ]]; then
      clear
      UserMenu_Modify
    elif pass_validator $passWord; then
      echo -e "$password\n$password" | ocpasswd -c /etc/ocserv/ocpasswd $menu
      clear
      echo -e "\nThe password for user '${YELLOW}$menu${EC}' has been successfully changed."
      UserMenu_Modify

    fi
    break
  done

}

# Change an existing username
function UserMenu_Modify_ChangeUser() {

  PS3="Select a user to change username: "
  LIST=$(awk -F: '{print $1}' "/etc/ocserv/ocpasswd")
  options=($LIST)
  if [[ -z $LIST ]]; then
    echo "No users found."
    UserMenu
  fi
  select menu in "${options[@]}"; do
    echo -e "\nyou picked $menu ($REPLY)"
    if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
      clear
      echo -e "${RED}Wrong number. User not found.${EC}"
      UserMenu_Modify_ChangeUser
    else
      echo -n "Please enter a new username for $menu: "
      read userInput
      if [[ -n $userInput ]]; then
        newname=$userInput
        sed -i "s/\b$menu\b/$newname/" /etc/ocserv/ocpasswd
        clear
        echo -e "${CYAN}$menu${EC}'s username has been replaced by ${CYAN}$newname${EC}."
        UserMenu_Modify
      fi
    fi

    break
  done
}

# Question for activating config per user
function UserMenu_Modify_ConfigPerUser_Question() {
  echo -e "If you want to have a specific configuration for a user, you need to enable this feature first."
  echo -e "\nDo you want to enable Config-Per-User ?"
  select yn in "Yes" "No"; do
    case $yn in
    Yes)
      sed -i 's/#config-per-user = \/etc\/ocserv\/config-per-user\//config-per-user = \/etc\/ocserv\/config-per-user\//' $ocservConfig
      sed -i 's/#config-per-group = \/etc\/ocserv\/config-per-group\//config-per-group = \/etc\/ocserv\/config-per-group\//' $ocservConfig
      clear
      echo "Config-per-user is Enabled"
      UserMenu_Modify_ConfigPerUser

      ;;
    No)
      clear
      UserMenu_Modify
      ;;
    esac
  done
}

# Config per user
function UserMenu_Modify_ConfigPerUser() {
  PS3="Please pick a user: "
  LIST=$(awk -F: '{print $1}' "/etc/ocserv/ocpasswd")
  options=($LIST)
  if [[ -z $LIST ]]; then
    echo "No users found."
    UserMenu
  fi
  select menu in "${options[@]}"; do
    echo -e "\nYou picked $menu ($REPLY)"
    if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then

      echo -e "${RED}Wrong number. User not found.${EC}"
      UserMenu_Modify
    else
      if ! [[ -d "/etc/ocserv/config-per-user/" ]]; then
        mkdir /etc/ocserv/config-per-user/
      elif ! [[ -f "/etc/ocserv/config-per-user/$menu" ]]; then
        touch /etc/ocserv/config-per-user/$menu
      fi

      # DNS
      while true; do
        echo -n "If you want to change the DNS for this user, enter it (if you want to use the default DNS, leave it blank): "
        read userInputDns
        if [[ -z $userInputDns ]]; then
          USERDNS=$PDNS
          echo -e "${YELLOW}DNS will be set to $USERDNS${EC}"
          break
        else
          if valid_ip $userInputDns; then
            USERDNS=$userInputDns
            stat='will be used as your Primary DNS'
            echo -e "$USERDNS" "${GREEN}$stat${EC}"
            break
          else
            stat='is not a valid IP address.'
            echo -e "$userInputDns" "${RED}$stat${EC}"
          fi
        fi
      done

      until [[ $userInputMaxScl =~ ^[0-9]+$ ]]; do
        echo -n "How many devices can connect to the server with this user account at the same time(0 means unlimited): "
        read userInputMaxScl
      done
      if [[ $userInputMaxScl =~ ^[0-9]+$ ]]; then
        USER_MAX_SAME_CLIENT=$userInputMaxScl
        echo -e "${YELLOW}Max_Same_Client will be $USER_MAX_SAME_CLIENT${EC} "
      else
        echo -e "${RED}You must enter a number${EC}"
      fi
      while true; do
        echo -n "If you want this user can connect to the server with a different domain, please enter your new domain name(Leave blank to use default Domain): "
        read userInputDomain
        if [[ -z $userInputDomain ]]; then
          echo -e "${YELLOW}Default domain will be used${EC}"
          break
        else
          if domain_validator $userInputDomain; then
            stat='will be used as this user Domain'
            echo -e "$userInputDomain" "${GREEN}$stat${EC}"
            USER_NEW_DOMAIN=$userInputDomain
            echo -e "${YELLOW}You entered a new domain for this user.
If you want to add a Certificate for this domain refer to Add New Certificate from OCServ Menu${EC}"
            break
          else
            echo -e "${RED}Domain structure is incorrect.${EC}"
          fi
        fi
      done

      echo -n "The time (in seconds) that a client is allowed to stay idle before being disconnected (Leave it blank to disable): "
      read userInputClIdle
      echo -n "The time (in seconds) that a Mobile client is allowed to stay idle before being disconnected (Leave it blank to disable): "
      read userInputClmidle
      unlink /etc/ocserv/config-per-user/$menu
      echo "max-same-clients = $USER_MAX_SAME_CLIENT" >>/etc/ocserv/config-per-user/$menu
      if [[ -n $userInputDomain ]]; then
        echo "default-domain = $USER_NEW_DOMAIN" >>/etc/ocserv/config-per-user/$menu
      fi
      echo "dns = $USERDNS" >>/etc/ocserv/config-per-user/$menu
      if [[ -n $userInputClIdle ]]; then
        USER_NEW_IDLE_TIME=$userInputClIdle
        echo "idle-timeout = $USER_NEW_IDLE_TIME" >>/etc/ocserv/config-per-user/$menu
      else
        echo "#idle-timeout = 1200" >>/etc/ocserv/config-per-user/$menu
      fi
      if [[ -n $userInputClmidle ]]; then
        USER_MOBILE_NEW_IDLE_TIME=$userInputClmidle
        echo "idle-timeout = $USER_MOBILE_NEW_IDLE_TIME" >>/etc/ocserv/config-per-user/$menu
      else
        echo "#mobile-idle-timeout = 1800" >>/etc/ocserv/config-per-user/$menu
      fi
      clear
      echo -e "A new configuration has been added for the user ${YELLOW}$menu${EC}."
      read -p "Restarting OCServ Service to apply the changes..." -t 5
      systemctl restart ocserv
      clear
      echo -e "\n${GREEN}DONE${EC}"
      UserMenu_Modify
    fi

    break
  done

}

# User modification menu
function UserMenu_Modify() {
  echo -e "\n${GREEN}You can change the username or password individually.${EC}"
  echo -ne "
    ${BOLDGREEN}User Modification Menu${EC}
    ${RED}1${EC}) Change an existing Username (Only the Username will change. The password will remain intact)
    ${RED}2${EC}) Change Passowrd (Change the Password for an existing User)
    ${RED}3${EC}) Config per User
    ${RED}4${EC}) Back to Main Menu
    ${RED}0${EC}) Exit
    Choose an option:  "
  read -r ans
  case $ans in
  1)
    clear
    UserMenu_Modify_ChangeUser
    ;;
  2)
    clear
    pass_change
    ;;
  3)
    clear
    if [ -d "/etc/ocserv/config-per-user/" ]; then
      UserMenu_Modify_ConfigPerUser
    else
      UserMenu_Modify_ConfigPerUser_Question
    fi
    ;;
  4)
    clear
    mainmenu
    ;;
  0)
    clear
    echo "If you need anything, I'm here!
Bye Bye"
    exit 0
    ;;
  *)
    clear
    echo "$ans is Wrong."
    UserMenu_Modify
    ;;
  esac

}

# User control section
function UserMenu() {
  echo -ne "
    ${BOLDGREEN}USER MENU${EC}
      ${RED}1${EC}) Add a New User
      ${RED}2${EC}) Revoke a User
      ${RED}3${EC}) Modify an existing User
      ${RED}4${EC}) Show All Users
      ${RED}5${EC}) Show Connected Users
      ${RED}6${EC}) Disconnect a User      
      ${RED}7${EC}) Back to Main Menu
      ${RED}0${EC}) Exit
    Choose an option:  "
  read -r ans
  case $ans in
  1)
    UserMenu_ADD
    ;;
  2)
    clear
    UserMenu_Revoke
    ;;
  3)
    clear
    UserMenu_Modify
    ;;
  4)
    clear
    echo -e "${YELLOW}List of all users:${EC}"
    awk -F: '{print $1}' "/etc/ocserv/ocpasswd"
    UserMenu
    ;;
  5)
    clear
    echo -e "${YELLOW}List of connected users:${EC}"
    occtl show users | awk '(NR>1) {print $2"-->ClientIP:"$4}'
    UserMenu
    ;;
  6)
    clear
    echo -e "${YELLOW}List of connected users:${EC}"
    UserDC
    ;;
  7)
    clear
    mainmenu
    ;;
  0)
    clear
    echo "If you need anything, I'm here!
Bye Bye"
    exit 0
    ;;
  *)
    clear
    echo "$ans is Wrong."
    UserMenu
    ;;
  esac
}

# Disconnect a User
function UserDC() {
  PS3="Pick a connected user to disconnect: "
  LIST=$(occtl show users | awk '(NR>1) {print $2"-->ClientIP:"$4}')
  options=($LIST)
  if [[ -z $LIST ]]; then
    echo "There are no users connected."
    UserMenu
  fi
  select menu in "${options[@]}"; do
    echo -e "\nyou picked $menu ($REPLY)"
    if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
      clear
      echo "You picked $REPLY"
      echo -e "${RED}Wrong number. User not found.${EC}"
      UserDC
    else
      local CONTINUE=""
      until [[ $CONTINUE =~ (y|n) ]]; do
        read -rp "Are you sure about disconnecting this user? [y/n]: " -e CONTINUE
      done
      if [ $CONTINUE == n ]; then
        clear
        UserMenu
      else
        occtl show users | awk '(NR>1) {print $1}' >templist.txt
        DC=$(sed -n "$REPLY{p;q}" templist.txt)
        occtl disconnect id $DC
        clear
        echo -e "The User account "${YELLOW}$menu${EC}" has been successfully disconnected. \n"
        unlink templist.txt
        UserMenu
      fi
    fi
    break
  done
}

# Add a new Certificate
function AddCert() {
  echo -e "${RED}*Please note${EC}, adding a new certificate in this section, only makes you able to connect to the server with more domains.
  If you want to create a new domain with a new configuration (such as adding a new port) for the server, you should refer to the ${GREEN}Add Multiple OCServ${EC} from the Main Menu.\n "
  echo -e "${RED}*Please note${EC}, You need a new Domain and an Email. ${RED}*Both are required*${EC}. ${CYAN}New Email is not necessary. You can use the Emails you used before.${EC}\n "
  if email_validator $email; then
    if newDomain $domainInput; then
      userInputnewDomain=$domainInput
      userInputnewEmail=$email
    fi
    if [[ $(ps -acx | grep apache | wc -l) > 0 ]]; then
      systemctl stop apache2
      certbot certonly --standalone --preferred-challenges http --agree-tos --email $userInputnewEmail -d $userInputnewDomain
      systemctl start apache2
    fi
    if [[ $(ps -acx | grep nginx | wc -l) > 0 ]]; then
      systemctl stop nginx
      certbot certonly --standalone --preferred-challenges http --agree-tos --email $userInputnewEmail -d $userInputnewDomain
      systemctl start nginx
    fi
    if [[ $(ps -acx | grep apache | wc -l) -eq 0 ]] && [[ $(ps -acx | grep nginx | wc -l) -eq 0 ]]; then
      certbot certonly --standalone --preferred-challenges http --agree-tos --email $userInputnewEmail -d $userInputnewDomain
    fi
    echo "-\---------\----------\----------\-----------\-----------\-"
    echo -e "If the above processing is done ${GREEN}successfully and without errors${EC}, your certificate is located in the following path.
  ${YELLOW}Certificate path:${EC} /etc/letsencrypt/live/$userInputnewDomain/
  If you see an error and the operation fails, try to fix it. LetsEncrypt errors usually occur due to incorrect setting of the DNS records, overuse of a domain, etc."
    echo "-/---------/----------/----------/-----------/-----------/-"
    LetsEncrypt_Menu
  fi

}

# Change the certificate in the config file of the desired OCServ
function Cert_Change() {
  CERTSNUMBER=$(ls -1U /etc/letsencrypt/live/ | wc -l)
  CERTLISTNAME=$(for dir in /etc/letsencrypt/live/*/; do basename "$dir"; done)
  CONFLISTNAME=$(for file in /etc/ocserv/ocserv*.conf; do basename "$file"; done)
  SERVERLISTNUMBER=$(stat -c %n /lib/systemd/system/ocserv*.service | wc -l)
  SERVERLISTNAME=$(for file in /lib/systemd/system/ocserv*.service; do basename "$file"; done | awk -F. '{print $1}')
  echo "Each OCServ has its own configuration and each configuration contains a certificate. 
In this section, you can change the certificate in the config file of the desired OCServ."
  echo -e "You already have ${YELLOW}$SERVERLISTNUMBER${EC} OCServ service(s)"
  PS3="Please pick a service to change the certificate: "
  options1=($SERVERLISTNAME)
  if [[ -z $SERVERLISTNAME ]]; then
    echo -e "${RED}No Service Found${EC}"
  else
    select menu1 in "${options1[@]}"; do
      echo -e "\nYou picked ${GREEN}$menu1${EC} ($REPLY)"
      if [[ ${REPLY} -gt ${#options1[@]} ]] || ! [[ ${REPLY} =~ ^[0-9]+$ ]]; then
        clear
        echo "${REPLY}"
        echo -e "${RED}Wrong number. Service not found${EC}"
        Cert_Change
      else
        local CONTINUE=""
        until [[ $CONTINUE =~ (y|n) ]]; do
          read -rp "Please Confirm [y/n]: " -e CONTINUE
        done
        if [[ $CONTINUE == n ]]; then
          clear
          LetsEncrypt_Menu
        else
          echo "Please specify whether you want to use a non-Letsencrypt certificate you currently have or you want to use a LetsEncrypt certificate."
          echo "   1) I already have a non-LetsEncrypt Certificate"
          echo "   2) I want to use LetsEncrypt"
          read -r -p "Please select one [1-2]: " -e options
          case $options in
          1)
            read -e -p "Enter the path to the Certificate '.cert OR .pem OR .crt' file (Example : /your/cert/path/cert.pem):" CERTPATH
            read -e -p "Enter the path to the Certificate .key file (Example : /your/cert/path/cert.key):" KEYPATH
            sed -i "/server-cert = /c\server-cert = \/etc\/letsencrypt\/live\/${menu2}\/fullchain.pem" /etc/ocserv/$menu1.conf
            sed -i "/server-key = /c\server-key = \/etc\/letsencrypt\/live\/${menu2}\/privkey.pem" /etc/ocserv/$menu1.conf
            sed -i "/server-cert =/c\server-cert = ${CERTPATH//\//\\/}" /etc/ocserv/$menu1.conf
            sed -i "/server-key =/c\server-key = ${KEYPATH//\//\\/}" /etc/ocserv/$menu1.conf
            clear
            echo -e "$CERTPATH and $KEYPATH has been successfully replaced in ${YELLOW}$menu1${EC}"
            LetsEncrypt_Menu
            ;;
          2)
            echo -e "\nYou already have ${YELLOW}$CERTSNUMBER${EC} obtained certificate(s) with LetsEncrypt"
            echo "If you want to add a new Certificate enter 0. Otherwise, choose one of the obtained certificates below."
            PS3="Please pick a Certificate. (Enter 0 for add a new Certificate): "
            options2=($CERTLISTNAME)
            select menu2 in "${options2[@]}"; do
              echo -e "\nYou picked ${GREEN}$menu2${EC}($REPLY)"
              if [[ $REPLY -eq 0 ]]; then
                if email_validator $email; then
                  if newDomain $domainInput; then
                    userInputnewDomain=$domainInput
                    userInputnewEmail=$email
                    clear
                    if [[ $(ps -acx | grep apache | wc -l) > 0 ]]; then
                      systemctl stop apache2
                      certbot certonly --standalone --preferred-challenges http --agree-tos --email $userInputnewEmail -d $userInputnewDomain
                      systemctl start apache2
                    fi
                    if [[ $(ps -acx | grep nginx | wc -l) > 0 ]]; then
                      systemctl stop nginx
                      certbot certonly --standalone --preferred-challenges http --agree-tos --email $userInputnewEmail -d $userInputnewDomain
                      systemctl start nginx
                    fi
                    if ! [[ $(ps -acx | grep apache | wc -l) > 0 ]] && ! [[ $(ps -acx | grep nginx | wc -l) > 0 ]]; then
                      certbot certonly --standalone --preferred-challenges http --agree-tos --email $userInputnewEmail -d $userInputnewDomain
                    fi
                    echo "-\---------\----------\----------\-----------\-----------\-"
                    echo -e "If the above processing is done ${GREEN}successfully and without errors${EC}, your certificate is located in the following path.
  ${YELLOW}Certificate path:${EC} /etc/letsencrypt/live/$userInputnewDomain/
  If you see an error and the operation fails, try to fix it. LetsEncrypt errors usually occur due to incorrect setting of the DNS records, overuse of a domain, etc."
                    echo "-/---------/----------/----------/-----------/-----------/-"
                    menu2=$domainInput
                  fi
                fi
              fi
              if [[ ${REPLY} -gt ${#options2} ]]; then
                echo "${REPLY}"
                echo -e "${RED}Wrong number. Option not found${EC}"
              else
                local CONTINUE=""
                until [[ $CONTINUE =~ (y|n) ]]; do
                  read -rp "Please confirm that you want to use $menu2 certificate [y/n]: " -e CONTINUE
                done
                if [[ $CONTINUE == y ]]; then
                  sed -i "/server-cert = /c\server-cert = \/etc\/letsencrypt\/live\/${menu2}\/fullchain.pem" /etc/ocserv/$menu1.conf
                  sed -i "/server-key = /c\server-key = \/etc\/letsencrypt\/live\/${menu2}\/privkey.pem" /etc/ocserv/$menu1.conf
                  clear
                  echo -e "${GREEN}$menu2${EC} has been successfully replaced for ${YELLOW}$menu1${EC}"
                  LetsEncrypt_Menu
                else
                  clear
                  LetsEncrypt_Menu
                fi
              fi
            done
            ;;
          *)
            echo "$(tput setaf 1)Invalid option$(tput sgr 0)"
            ;;
          esac

        fi

      fi

    done

  fi

}

# OCServ Menu
function OCServMenu() {
  echo -ne "
    ${BOLDGREEN}OCServ Server Menu${EC}
      ${RED}1${EC}) Check OCServ service status
      ${RED}2${EC}) Restart OCServ service
      ${RED}3${EC}) Stop OCServ service
      ${RED}4${EC}) FIX OCServ Futex Error (Ubuntu 22.04)
      ${RED}5${EC}) Show Logs
      ${RED}6${EC}) Change Port
      ${RED}7${EC}) Back to Main Menu
      ${RED}0${EC}) Exit
    Choose an option:  "
  read -r ans
  case $ans in
  1)
    LIST=$(for file in /lib/systemd/system/ocserv*.service; do basename "$file"; done)
    if [[ ${serverlist} > 0 ]]; then
      echo "You already have ${serverlist} OCServ Service(s)."
      PS3="Pick a Service: "
      options=($LIST)
      if [[ -z $LIST ]]; then
        echo "No Service found."
      fi
      select menu in "${options[@]}"; do
        echo -e "\nYou picked ${GREEN}$menu${EC} ($REPLY)"
        if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
          clear
          echo -e "${RED}Wrong number. Option not found.${EC}"
          OCServMenu
        fi
        break
      done
    fi
    clear
    echo -e "${YELLOW}-\---------\----------\----------\-----------\-----------\-${EC}"
    systemctl status $menu
    echo -e "${YELLOW}-/---------/----------/----------/-----------/-----------/-${EC}"
    echo -e "\nIf you see ${RED}'error connecting to sec-mod socket'${EC}, There is no problem with that. A few lines below the error, it has been fixed automatically."
    testvercomp $VERSION_ID "22.04" "="
    if [[ $VERID -eq 0 ]]; then
      echo -e "If you see ${RED}'The futex facility returned an unexpected error code'${EC}, Refer to ${GREEN}'FIX OCServ Futex Error'${EC} from the Menu to fix it."
    fi
    OCServMenu
    ;;
  2)
    LIST=$(for file in /lib/systemd/system/ocserv*.service; do basename "$file"; done)
    if [[ ${serverlist} > 0 ]]; then
      echo "You already have ${serverlist} OCServ Service(s)."
      PS3="Pick a Service(Enter 0 to restart all services): "
      options=($LIST)
      if [[ -z $LIST ]]; then
        echo "No Service found."
      fi
      select menu in "${options[@]}"; do
        echo -e "\nYou picked ${GREEN}$menu${EC} ($REPLY)"
        if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
          clear
          echo -e "${RED}Wrong number. Option not found.${EC}"
          OCServMenu
        fi
        break
      done
    fi
    if [[ $REPLY -ne 0 ]]; then
      clear
      systemctl restart $menu
      string="Restarting ${menu}..."
      for ((i = 0; i <= ${#string}; i++)); do
        printf '%s' "${string:$i:1}"
        sleep 0.$(((RANDOM % 1) + 1))
      done
      if (systemctl is-active --quiet $menu); then
        echo -e "\nStatus : $(systemctl is-active $menu)"
      else
        echo -e "\nStatus : $(systemctl is-active $menu)"
        echo -e "The service does not activate correctly. To check the problem, refer to the 'Service Status' menu."
      fi
    else
      clear
      systemctl restart --all ocserv*.service &>/dev/null
      echo "All services have been restarted"
      echo "Status:"
      for file in $serverlist_names; do
        echo "$file : $(systemctl is-active $file)"
      done
    fi
    OCServMenu
    ;;
  3)
    LIST=$(for file in /lib/systemd/system/ocserv*.service; do basename "$file"; done)
    if [[ ${serverlist} > 0 ]]; then
      echo "You already have ${serverlist} OCServ Service(s)."
      PS3="Pick a Service(Enter 0 to stop all services): "
      options=($LIST)
      if [[ -z $LIST ]]; then
        echo "No Service found."
      fi
      select menu in "${options[@]}"; do
        echo -e "\nYou picked ${GREEN}$menu${EC} ($REPLY)"
        if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
          clear
          echo -e "${RED}Wrong number. Option not found.${EC}"
          OCServMenu
        fi
        break
      done
    fi
    if [[ $REPLY -ne 0 ]]; then
      clear
      if ! (systemctl is-active --quiet $menu); then
        echo "Service is already stopped"
        echo -e "\nStatus : $(systemctl is-active $menu)"
      else
        systemctl stop $menu
        echo "DONE"
        echo -e "\nStatus : $(systemctl is-active $menu)"
      fi
    else
      clear
      systemctl stop --all ocserv*.service &>/dev/null
      echo "All services have stopped"
      echo "Status:"
      for file in $serverlist_names; do
        echo "$file : $(systemctl is-active $file)"
      done
    fi
    OCServMenu
    ;;
  4)
    clear
    fix_futex_error
    ;;
  5)
    clear
    journalctl -eu ocserv.service
    OCServMenu
    ;;
  6)
    conflist=$(stat -c %n /etc/ocserv/ocserv*.conf | wc -l)
    if [[ ${conflist} > 0 ]]; then
      echo "You already have ${conflist} OCServ Service(s)."
      PS3="Pick a service to change the Port: "
      LIST=$(for file in /etc/ocserv/ocserv*.conf; do basename "$file"; done)
      options=($LIST)
      if [[ -z $LIST ]]; then
        echo "No Service found."
      fi
      select menu in "${options[@]}"; do
        echo -e "\nYou picked ${GREEN}$menu${EC} ($REPLY)"
        if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
          clear
          echo -e "${RED}Wrong number. Option not found.${EC}"
          OCServMenu
        fi
        break
      done
    fi
    clear
    newPortnumber $newPort
    sed -i "s/\(tcp-port =\) [0-9]\+/\1 $newPort/" /etc/ocserv/$menu
    sed -i "s/\(udp-port =\) [0-9]\+/\1 $newPort/" /etc/ocserv/$menu
    clear
    echo "######################"
    echo -e "${GREEN}Port changed to${EC} ${YELLOW}$newPort${EC}"
    echo "######################"
    ufw allow $newPort
    pickedconf=$(for file in $menu; do basename "$file"; done | awk -F. '{print $1}')
    systemctl restart $pickedconf
    OCRES="Restarting $pickedconf Service..."
    for ((i = 0; i <= ${#OCRES}; i++)); do
      printf '%s' "${OCRES:$i:1}"
      sleep 0.$(((RANDOM % 1) + 1))
    done
    sleep 2
    echo -e "${GREEN}DONE${EC}"
    OCServMenu
    ;;
  7)
    clear
    mainmenu
    ;;
  0)
    clear
    echo "If you need anything, I'm here!
Bye Bye"
    exit 0
    ;;
  *)
    clear
    echo "$ans is Wrong."
    OCServMenu
    ;;
  esac
}

# LetsEncrypt Menu
function LetsEncrypt_Menu() {
  echo -ne "
    ${BOLDGREEN}LetsEncrypt Menu${EC}
      ${RED}1${EC}) Add New Certificate
      ${RED}2${EC}) Remove an existing Certificate
      ${RED}3${EC}) Change the Certificate of active OCServs
      ${RED}4${EC}) Show Certificates
      ${RED}5${EC}) Force Renew LetsEncrypt Certificates
      ${RED}6${EC}) Back to Main Menu
      ${RED}0${EC}) Exit
    Choose an option:  "
  read -r ans
  case $ans in
  1)
    clear
    AddCert
    ;;
  2)
    clear
    certbot delete
    LetsEncrypt_Menu
    ;;
  3)
    clear
    Cert_Change
    ;;
  4)
    clear
    echo "-\---------\----------\----------\-----------\-----------\-"
    certbot certificates
    echo "-/---------/----------/----------/-----------/-----------/-"
    LetsEncrypt_Menu
    ;;
  5)
    clear
    CERTLISTNAME=$(for dir in /etc/letsencrypt/live/*/; do basename "$dir"; done)
    CERTSNUMBER=$(ls -1U /etc/letsencrypt/live/ | wc -l)
    echo -e "You already have $CERTSNUMBER certificate(s)"
    PS3="Please pick a Certificate. (Enter 0 for cancel): "
    options=($CERTLISTNAME)
    select menu in "${options[@]}"; do
      echo -e "\nYou picked ${GREEN}$menu${EC} ($REPLY)"
      if [[ $REPLY -eq 0 ]]; then
        LetsEncrypt_Menu
      elif [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
        echo -e "${RED}Wrong Number${EC}"
        LetsEncrypt_Menu
      fi
      if (systemctl is-active --quiet nginx); then
        systemctl stop nginx
        echo "1" | certbot certonly --force-renew -d $menu
        systemctl start nginx
        systemctl is-active --quiet nginx && echo Starting Nginx [OK]
        LetsEncrypt_Menu
      elif (systemctl is-active --quiet apache2); then
        systemctl stop apache2
        echo "1" | certbot certonly --force-renew -d $menu
        systemctl start apache2
        systemctl is-active --quiet apache2 && echo Starting Apache [OK]
        LetsEncrypt_Menu
      else
        echo "1" | certbot certonly --force-renew -d $menu
        LetsEncrypt_Menu
      fi

    done

    ;;

  6)
    clear
    mainmenu
    ;;
  0)
    clear
    echo "If you need anything, I'm here!
Bye Bye"
    exit 0
    ;;
  *)
    clear
    echo "$ans is Wrong."
    LetsEncrypt_Menu
    ;;
  esac
}

# Fix OCServ Futex Error for ubuntu 22.04
function fix_futex_error() {
  local CONTINUE=""
  echo -e "There is no need to do this if the OCServ works without problems. Just if you see the following error in OCServ Service Status:
  ${YELLOW}'The futex facility returned an unexpected error code.'${EC}
you can continue the operation to fix it."
  echo -e "\n${CYAN}Please note, this operation may take a long time to complete. Please be patient and have a coffee!${EC}"
  until [[ $CONTINUE =~ (y|n) ]]; do
    read -rp "Do you wish to continue? [y/n]: " -e CONTINUE
  done
  if [[ $CONTINUE == "n" ]]; then
    OCServMenu
  else
    apt install -y git ruby-ronn libbsd-dev libsystemd-dev libpcl-dev libwrap0-dev libgnutls28-dev libev-dev libpam0g-dev liblz4-dev libseccomp-dev libreadline-dev libnl-route-3-dev libkrb5-dev libradcli-dev libcurl4-gnutls-dev libcjose-dev libjansson-dev libprotobuf-c-dev libtalloc-dev libhttp-parser-dev protobuf-c-compiler gperf nuttcp lcov libuid-wrapper libpam-wrapper libnss-wrapper libsocket-wrapper gss-ntlmssp haproxy iputils-ping freeradius gawk gnutls-bin iproute2 yajl-tools tcpdump
    git clone https://gitlab.com/openconnect/ocserv.git
    cd ocserv
    autoreconf -fvi
    ./configure && make
    make install
    sed -i "s/ExecStart=\/usr\/sbin\/ocserv/ExecStart=\/usr\/local\/sbin\/ocserv/" /lib/systemd/system/ocserv.service
    systemctl daemon-reload
    systemctl restart ocserv
    echo "###################"
    echo -e "${GREEN}DONE${EC}"
    echo "###################"
    systemctl status ocserv
    echo -e "\n${GREEN}Please check the status above. The FUTEX error should be gone.${EC}"
  fi
}

# The question for adding a new OCServ process
function AddMultipleOC_Question() {
  echo -e "Adding a new OCServ process means using a completely separate config from the main process.
  Like using a new Port, new Domain and Certificate and any new changes you are considering.
  After completing the following steps, You will have access to all your ${YELLOW}OCServ's${EC} in the ${GREEN}OCServ menu${EC}.
  Do you wish to ${GREEN}continue?${EC}"
  select yn in "Yes" "No"; do
    case $yn in
    Yes)
      AddMultipleOC
      ;;
    No)
      clear
      mainmenu
      ;;
    *) echo -e "${RED}invalid response. Choose y or n${EC}" ;;
    esac
  done
}

# Add a Domain
function newDomain() {

  echo -n "Enter your Domain (Like example.com or sub.example.com): "
  read domainInput
  domainIP=$(getent hosts $domainInput | awk '{ print $1 }')
  serverIP_domainIP_match=$(hostname -I | grep -o $domainIP 2>/dev/null)
  if [[ -z $domainInput ]]; then
    echo -e "${RED}Domain is required${EC}"
    newDomain
  elif domain_validator $domainInput; then
    if [[ -z $domainIP ]]; then
      echo -e "The domain you entered does not exist.
${CYAN}You may have entered the domain incorrectly or you may not have set the DNS record of the domain correctly from your domain panel.${EC}"
      newDomain
    else
      if ! [[ $domainIP == $serverIP_domainIP_match ]]; then
        echo -e "${RED}The domain you entered does not match the IP of your server.${EC}
${YELLOW}The IP of the Domain you entered: ${EC}
    $domainIP
${YELLOW}Your Server IP: ${EC} 
    $(hostname -I)
${CYAN}You may have entered the domain incorrectly or you may not have set the DNS record of the domain correctly from your domain panel.${EC}"
        newDomain
      fi
    fi
    stat='will be used as your Domain'
    echo -e "$domainInput" "${GREEN}$stat${EC}"
  else
    echo -e "${RED}Your domain structure is incorrect.${EC}"
    newDomain
  fi
}

# Port Number
function newPortnumber() {
  echo -n "Enter the new Port Number(Leave blank to use a random port): "
  read newPort
  if [[ -z $newPort ]]; then
    rnewPort=$(shuf -i 1025-65000 -n 1)
    newPort=$rnewPort
    echo -e "${YELLOW}Port Number will be '$newPort'${EC}"
  else
    minport=1024
    if ! [[ $newPort =~ ^[0-9]+$ ]]; then
      echo -e "${RED}Port number cannot contain letters. You must enter a Number${EC}"
      newPortnumber
    elif [[ $newPort -lt $minport ]] && [[ $newPort -gt 1 ]]; then
      echo -e "${RED}You want to use a port less than 1024 that may be used for a specific service.${EC}"
      read -p "Do you want to proceed? (y/n) " yn
      case $yn in
      [yY])
        echo -e "${YELLOW}Port will be: '$newPort'${EC}"
        ;;
      [nN])
        newPortnumber
        ;;
      *)
        echo -e "${RED}invalid response. Choose y or n${EC}"
        newPortnumber
        ;;
      esac
    elif [[ $newPort -lt 1 ]] || [[ $newPort -gt 65535 ]]; then
      echo -e "${RED}Port number must be between 1 and 65535.${EC}"
      newPortnumber
    else
      echo -e "${YELLOW}Port will be: '$newPort'${EC}"
    fi
  fi

}

# Add a new Private IP
function newPrivateIP() {
  echo -n "Enter the new Private IP address (This is not your server Public IP)(Leave it blank for 10.10.${newserv}0.0): "
  read newPIP
  if [[ -z $newPIP ]]; then
    newPIP=10.10.${newserv}0.0
    echo -e "${YELLOW}Your new Private IP will be '$newPIP'${EC}"
  else
    if valid_private_ip $newPIP; then
      stat='will be used as your Private IP'
      echo -e "${GREEN}$newPIP${EC}" "$stat"
    else
      stat='is not a Private IP address. '
      echo -e "$newPIP" "${RED}$stat${EC}"
      newPrivateIP
    fi
  fi
}

function cert_p80() {
  if [[ $(ps -acx | grep apache | wc -l) > 0 ]]; then
    systemctl stop apache2
    if [ $findCert ]; then
      echo "1" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
      systemctl start apache2
    else
      echo "n" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
      systemctl start apache2
    fi
  fi
  if [[ $(ps -acx | grep nginx | wc -l) > 0 ]]; then
    systemctl stop nginx
    if [ $findCert ]; then
      echo "1" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
    else
      echo "n" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
    fi
    systemctl start nginx
  fi
  if [[ $(ps -acx | grep nginx | wc -l) == 0 ]] && [[ $(ps -acx | grep apache2 | wc -l) == 0 ]]; then
    if [ $findCert ]; then
      echo "1" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
    else
      echo "n" | certbot certonly --standalone --preferred-challenges http --agree-tos --email ${EMAIL} -d ${DOMAIN}
    fi
  fi
  check_port80=$(lsof -i tcp:80 | awk 'NR!=1 {print $1}')
  if [[ $(ps -acx | grep nginx | wc -l) == 0 ]] && [[ $(ps -acx | grep apache2 | wc -l) == 0 ]] && [[ $check_port80 ]]; then
    echo -e "${RED}$check_port80${EC} is using port ${GREEN}80${EC}. Please stop it first and try again."
    exit 1
  fi

}

# Add Multiple OCServ
function AddMultipleOC() {
  i=$(ls -dq /lib/systemd/system/ocserv*.service | wc -l)
  newserv=$((++i))
  echo -e "\nPlease Answer the following questions :\n"
  # Domain
  domainList=$(($(stat -c %h /etc/letsencrypt/live/) - 2))
  if [[ $domainList > 0 ]]; then
    echo "You already have $domainList domain(s) registered in LetsEncrypt."
    echo -e "You can also use these domains to add a new OCServ. If you want to use a new Domain, Enter 0."
    PS3="Pick a Domain: "
    LIST=$(for dir in /etc/letsencrypt/live/*/; do basename "$dir"; done)
    options=($LIST)
    if [[ -z $LIST ]]; then
      echo "No Domain found."
    fi
    select menu in "${options[@]}"; do
      echo -e "\nYou picked ${GREEN}$menu${EC} ($REPLY)"
      if [[ $REPLY -gt ${#options[@]} ]] || ! [[ $REPLY =~ ^[0-9]+$ ]]; then
        clear
        echo -e "${RED}Wrong number. Option not found.${EC}"
        AddMultipleOC
      else
        if [[ $REPLY == 0 ]]; then
          if newDomain $domainInput; then
            DOMAIN=$domainInput
          fi
          # Email
          if email_validator $email; then
            EMAIL=$email
          fi
          cert_p80
        fi
      fi
      break
    done
  fi

  # PORT
  newPortnumber $newPort

  # Private IP
  newPrivateIP $newPIP

  # Primary DNS
  while true; do
    echo -n "Primary DNS (default is 8.8.8.8): "
    read primaryDns
    if [[ -z $primaryDns ]]; then
      primaryDns=$PDNS
      echo -e "${YELLOW}Primary DNS will be set to $primaryDns${EC}"
      break
    else
      if valid_ip $primaryDns; then
        stat='will be used as your Primary DNS'
        echo -e "$primaryDns" "${GREEN}$stat${EC}"
        break
      else
        stat='is not a valid IP address.'
        echo -e "$primaryDns" "${RED}$stat${EC}"
      fi
    fi
  done

  # Secondary DNS
  while true; do
    echo -n "Secondary DNS (default is 4.2.2.4): "
    read secDns
    if [[ -z $secDns ]]; then
      secDns=$SDNS
      echo -e "${YELLOW}Secondary DNS will be set to $secDns${EC}"
      break
    else
      if valid_ip $secDns; then
        stat='will be used as your Primary DNS'
        echo -e "$secDns" "${GREEN}$stat${EC}"
        break
      else
        stat='is not a valid IP address.'
        echo -e "$secDns" "${RED}$stat${EC}"
      fi
    fi
  done

  # Max Same Clients
  while true; do
    echo -n "The number of devices that can be used by a user at the same time (Default is 2)(0 is unlimited): "
    read new_max_samecl
    if [[ -z "$new_max_samecl" ]]; then
      new_max_samecl=$maxSameClient
      echo -e "${YELLOW}Max Same Client will be set to $new_max_samecl${EC}"
      break
    elif ! [[ $new_max_samecl =~ ^[0-9]+$ ]]; then
      echo -e "${RED}You must enter a Number${EC}"
    else
      echo -e "${YELLOW}Max Same Client will be set to '$new_max_samecl'${EC}"
      break
    fi
  done

  # Creating New OCServ Config and Service
  cp /lib/systemd/system/ocserv.service /lib/systemd/system/ocserv$newserv.service
  # Edit New Conf Location in Service
  sed -i "s/\/etc\/ocserv\/ocserv.conf/\/etc\/ocserv\/ocserv$newserv.conf/" /lib/systemd/system/ocserv$newserv.service
  # Create New Config File
  cp /etc/ocserv/ocserv.conf /etc/ocserv/ocserv$newserv.conf
  if [[ $REPLY == 0 ]]; then
    if [[ $(ps -acx | grep apache | wc -l) > 0 ]]; then
      systemctl stop apache2
      sed -i "/server-cert = /c\server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem" /etc/ocserv/ocserv$newserv.conf
      sed -i "/server-key = /c\server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem" /etc/ocserv/ocserv$newserv.conf
      systemctl start apache2
    fi
    if [[ $(ps -acx | grep nginx | wc -l) > 0 ]]; then
      systemctl stop nginx
      sed -i "/server-cert = /c\server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem" /etc/ocserv/ocserv$newserv.conf
      sed -i "/server-key = /c\server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem" /etc/ocserv/ocserv$newserv.conf
      systemctl start nginx
    fi
    if [[ $(ps -acx | grep nginx | wc -l) == 0 ]] && [[ $(ps -acx | grep apache2 | wc -l) == 0 ]]; then
      sed -i "/server-cert = /c\server-cert = \/etc\/letsencrypt\/live\/${DOMAIN}\/fullchain.pem" /etc/ocserv/ocserv$newserv.conf
      sed -i "/server-key = /c\server-key = \/etc\/letsencrypt\/live\/${DOMAIN}\/privkey.pem" /etc/ocserv/ocserv$newserv.conf
    fi
  else
    sed -i "/server-cert = /c\server-cert = \/etc\/letsencrypt\/live\/${menu}\/fullchain.pem" /etc/ocserv/ocserv$newserv.conf
    sed -i "/server-key = /c\server-key = \/etc\/letsencrypt\/live\/${menu}\/privkey.pem" /etc/ocserv/ocserv$newserv.conf
  fi

  sed -i "s/^tcp-port =.*/tcp-port = $newPort/" /etc/ocserv/ocserv$newserv.conf
  sed -i "s/^ipv4-network =.*/ipv4-network = $newPIP/" /etc/ocserv/ocserv$newserv.conf
  sed -i "/# dns = fc00::4be0/{n; s/dns =.*/dns = $primaryDns/}" /etc/ocserv/ocserv$newserv.conf
  sed -i "/dns = $primaryDns/{n; s/dns =.*/dns = $secDns/}" /etc/ocserv/ocserv$newserv.conf
  sed -i "s/^max-same-clients =.*/max-same-clients = $new_max_samecl/" /etc/ocserv/ocserv$newserv.conf
  #  NAT Rule
  echo "# NAT table rules OCServ$newserv
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s $newPIP/24 -o ${NET_INTER} -j MASQUERADE
COMMIT" >>/etc/ufw/before.rules
  #  Allow Forwading OcServ
  sed -i "/-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT/a # allow forwarding OCServ$newserv" /etc/ufw/before.rules
  sed -i "/# allow forwarding OCServ$newserv/a -A ufw-before-forward -s $newPIP\/24 -j ACCEPT" /etc/ufw/before.rules
  sed -i "/-A ufw-before-forward -s $newPIP\/24 -j ACCEPT/a -A ufw-before-forward -d $newPIP\/24 -j ACCEPT" /etc/ufw/before.rules
  # Back to OCServ Menu
  sleep 2
  clear
  echo -e "${GREEN}Starting OCServ$newserv Service${EC}"
  systemctl enable ocserv$newserv.service
  systemctl start ocserv$newserv
  ufw allow $newPort
  systemctl restart ufw
  sleep 2
  echo -e "New OCServ created and started successfully. You can access it through the main menu."
  echo "Status: $(systemctl is-active ocserv$newserv)"
  OCServMenu
}

# Question for Completely remove OCServ from the server (Letsencrypt will remain intact)
function OCremovequestion() {

  echo -e "\n${RED}By performing this operation, OCServ and all related files will be removed and cannot be returned${EC}\n"
  echo -ne "
    Are you sure you want to do this?
      ${RED}1${EC}) Yes, Remove everything
      ${RED}2${EC}) No, Back to Main Menu
      ${RED}0${EC}) Exit
    Choose an option:  "
  read -r ans
  case $ans in
  1)
    clear
    OCremove
    ;;
  2)
    clear
    mainmenu
    ;;
  0)
    clear
    echo "If you need anything, I'm here!
Bye Bye"
    exit 0
    ;;
  *)
    clear
    echo "$ans is Wrong."
    OCremovequestion
    ;;
  esac
}

# If Apache is installed on the server, the user must answer these questions
function apaChe() {
  if [[ $(ps -acx | grep apache | wc -l) > 0 ]]; then
    USE_APACHE=""
    until [[ $USE_APACHE =~ (y|n) ]]; do
      read -rp "Do you want to use Apache to obtain the certificate? [y/n]:" -e USE_APACHE
    done
    if [ $USE_APACHE == y ]; then
      until [[ $HAVE_DOMAIN =~ (y|n) ]]; do
        read -rp "Have you already set a domain for Apache? [y/n]:" -e HAVE_DOMAIN
      done
      if [[ $HAVE_DOMAIN == y ]]; then
        if newDomain $domainInput; then
          DOMAIN=$domainInput
          until [[ $CERT_EXIST =~ (y|n) ]]; do
            read -rp "Have you already obtained a Certificate for your Domain? [y/n]:" -e CERT_EXIST
          done
          if [ $CERT_EXIST == y ]; then
            read -e -p "Enter the path to the Certificate '.cert OR .pem OR .crt' file (Example : /your/cert/path/cert.pem):" CERTPATH
            read -e -p "Enter the path to the Certificate .key file (Example : /your/cert/path/cert.key):" KEYPATH
          fi
        fi
      else
        echo -e "${CYAN}You need to use a Domain. If you dont have one, buy one, then enter your new Domain below${EC}"
        if newDomain $domainInput; then
          DOMAIN=$domainInput
        fi
      fi
    else
      echo -e "${RED}Apache will be stoped during the installation${EC}"
      if newDomain $domainInput; then
        DOMAIN=$domainInput
      fi
    fi
  fi
}

# If Nginx is installed on the server, the user must answer these questions
function nginX() {
  if [[ $(ps -acx | grep nginx | wc -l) > 0 ]]; then
    USE_NGINX=""
    until [[ $USE_NGINX =~ (y|n) ]]; do
      read -rp "Do you want to use Nginx to obtain the certificate? [y/n]:" -e USE_NGINX
    done
    if [ $USE_NGINX == y ]; then
      until [[ $HAVE_DOMAIN =~ (y|n) ]]; do
        read -rp "Have you already set a domain for Nginx? [y/n]:" -e HAVE_DOMAIN
      done
      if [[ $HAVE_DOMAIN == y ]]; then
        if newDomain $domainInput; then
          DOMAIN=$domainInput
          until [[ $CERT_EXIST =~ (y|n) ]]; do
            read -rp "Have you already obtained a Certificate for your Domain? [y/n]:" -e CERT_EXIST
          done
          if [ $CERT_EXIST == y ]; then
            read -e -p "Enter the path to the Certificate '.cert OR .pem OR .crt' file (Example : /your/cert/path/cert.pem):" CERTPATH
            read -e -p "Enter the path to the Certificate .key file (Example : /your/cert/path/cert.key):" KEYPATH
          fi
        fi
      else
        echo -e "${CYAN}You need to use a Domain. If you dont have one, buy one, then enter your new Domain below${EC}"
        if newDomain $domainInput; then
          DOMAIN=$domainInput
        fi
      fi
    else
      echo -e "${RED}Nginx will be stoped during the installation${EC}"
      if newDomain $domainInput; then
        DOMAIN=$domainInput
      fi
    fi
  fi
}

# Private IP Validator
function valid_private_ip() {
  local ip=$1
  local stat=1

  if [[ $ip =~ ^[192]{3}\.[168]{3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || [[ $ip =~ ^[10]{2}\.[0-9]{1,2}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($ip)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 &&
      ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
  fi
  return $stat
}

# Valid IP Validator
function valid_ip() {
  local ip=$1
  local stat=1

  if [[ $ip =~ ^[1-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($ip)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 &&
      ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
  fi
  return $stat
}

# Domain Structure Validator
function domain_validator() {
  local domain=$1
  local stat=1

  if [[ $domain =~ ^[a-zA-Z0-9-]{1,62}\.[a-zA-Z1-9-]{2,62}\.[a-zA-Z1-9]{2,10}$ ]] || [[ $domain =~ ^[a-zA-Z0-9-]{2,62}\.[a-zA-Z1-9]{2,10}$ ]]; then
    OIFS=$IFS
    IFS='.'
    domain=($domain)
    IFS=$OIFS
    stat=$?
  fi
  return $stat
}

# Email Validator
function email_validator() {
  while true; do
    read -p "Enter your Email: " email
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$ ]] || [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,10}+\.[a-zA-Z]{2,10}$ ]] || [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]{2,10}+\.[a-zA-Z]{2,10}+\.[a-zA-Z]{2,10}$ ]]; then
      echo -e "$email ${GREEN}will be used as your Email.${EC}"
      break
    else
      echo -e "${RED}Email address '$email' is invalid.${EC}${CYAN} Example ${EC}: example@example.com"
    fi
  done

}

# Password Validator
function pass_validator() {
  read -s -p "Enter a Password: " password
  echo
  if ! [[ ${#password} > 5 ]]; then
    echo -e "${RED}Password must be more than 5 characters.${EC}"
    pass_validator
  else
    read -s -p "Confirm your password: " password2
    echo
  fi
  if [ "$password" = "$password2" ]; then
    passWord=$password
  else
    echo -e "${RED}Passwords do not match!${EC}"
    pass_validator
  fi

}

spin() {
  sp='/-\|'
  printf ' '
  while true; do
    printf '\b%.1s' "$sp"
    sp=${sp#?}${sp%???}
    sleep 0.05
  done
}

progressbar() {
  bar="##################################################"
  barlength=${#bar}
  n=$(($1 * barlength / 100))
  printf "\r[%-${barlength}s (%d%%)] " "${bar:0:n}" "$1"
}

# Check the prerequisites for running the script
if [[ -e /etc/ocserv/ocserv.conf ]]; then
  isRoot
  mainmenu
else
  isRoot
  checkOS
fi
