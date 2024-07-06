#!/bin/bash
#
#  |=================================================================================|
#  • Autoscript AIO Lite Menu By FN Project                                          |
#  • FN Project Developer @Rerechan02 | @PR_Aiman | @farell_aditya_ardian            |
#  • Copyright 2024 18 Marc Indonesia [ Kebumen ] | [ Johor ] | [ 上海，中国 ]       |
#  |=================================================================================|
#
clear

# [ Hosting Tempat File Tersimpan ]
link="https://raw.githubusercontent.com/megawatipepek/rere/main"

# // Membuat Koneksi Database
if [[ -z $(cat /etc/resolv.conf | grep "1.1.1.1") ]]; then cat <(echo "nameserver 1.1.1.1") /etc/resolv.conf > /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf; fi
if [[ -z $(cat /etc/ssh/sshd_config | grep "Port 22") ]]; then cat <(echo "Port 22") /etc/ssh/sshd_config > /etc/ssh/sshd_config.tmp && mv /etc/ssh/sshd_config.tmp /etc/ssh/sshd_config; fi
echo "Port 3303" >> /etc/ssh/sshd_config
systemctl restart ssh
clear

# [ Melakukan Restart Koneksi Database ]
systemctl daemon-reload ; systemctl restart ssh

# // Melakukan Update Dan Upgrade Data Server
apt update -y
apt upgrade -y
apt install binutils -y
apt install socat -y
apt install lolcat -y
apt install ruby -y
gem install lolcat
apt install wget curl -y
#apt install vnstat -y
apt install htop -y
apt install speedtest-cli -y
apt install cron -y
apt install figlet -y
apt install zip unzip -y
apt install jq -y
clear

# // Melakukan Pembuatan Directory
clear
mkdir -p /funny
sleep 1
mkdir -p /rere
sleep 1
mkdir -p /etc/slowdns
sleep 1
mkdir -p /etc/xray
sleep 1
mkdir -p /etc/websocket
sleep 1
mkdir -p /etc/xray
sleep 1
mkdir -p /etc/funny
sleep 1
mkdir -p /etc/funnt/limit
sleep 1
mkdir -p /etc/funny/limit/xray
sleep 1
mkdir -p /etc/funny/limit/xray/ip
sleep 1
mkdir -p /etc/funny/limit/xray/quota
sleep 1
mkdir -p /etc/funny/limit/ssh
sleep 1
mkdir -p /etc/funny/limit/ssh/ip
sleep 1
mkdir -p /etc/v2ray
sleep 1
mkdir -p /var
mkdir -p /var/lib
mkdir -p /var/lib/crot
chmod /var/lib/crot/*
mkdir -p /var/log
mkdir -p /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/error1.log
touch /var/log/xray/akses.log
touch /var/log/xray/access1.log
touch /var/log/xray/access2.log
touch /var/log/xray/access3.log
touch /var/log/xray/access4.log
touch /var/log/xray/access5.log
touch /var/log/xray/access6.log
touch /etc/funny/.l2tp
touch /etc/funny/.sstp
touch /etc/funny/.pptp
touch /etc/funny/.ptp
touch /etc/funny/.wireguard
touch /etc/funny/.socks5
chmod +x /var/log/xray/*
touch /etc/funny/limit/ssh/ip/syslog
touch /etc/funny/limit/ssh/ip/rere
mkdir -p /home/vps/public_html
echo "9999999" >> /etc/funny/limit/ssh/ip/syslog
echo "9999999" >> /etc/funny/limit/ssh/ip/rere
mkdir -p /etc/noobzvpns
clear

# // Meminta Konfigurasi
read -p "Input Your Domain: " domain
echo "${domain}" > /etc/xray/domain
clear

# // Membuat Layanan Selalu Berjalan
echo "0 0,6,12,18 * * * root backup
0,15,30,45 * * * * root /usr/bin/xp
0,15,30,45 * * * * root /usr/bin/wg-xp" >> /etc/crontab
systemctl daemon-reload
systemctl restart cron

# // Menginstall Dropbear
apt install dropbear -y
rm /etc/default/dropbear
rm /etc/issue.net
cat> /etc/issue.net << END
</strong> <p style="text-align:center"><b> <br><font color="#00FFE2"<br>┏━━━━━━━━━━━━━━━┓<br> RERECHAN STORE<br>┗━━━━━━━━━━━━━━━┛<br></font><br><font color="#00FF00"></strong> <p style="text-align:center"><b> <br><font color="#00FFE2">क═══════क⊹⊱✫⊰⊹क═══════क</font><br><font color='#FFFF00'><b> ★ [ ༆Hʸᵖᵉʳ᭄W̺͆E̺͆L̺͆C̺͆O̺͆M̺͆E̺͆
T̺͆O̺͆ M̺͆Y̺͆ S̺͆E̺͆R̺͆V̺͆E̺͆R̺͆ V͇̿I͇̿P͇̿ ] ★ </b></font><br><font color="#FFF00">ℝ𝕖𝕣𝕖𝕔𝕙𝕒𝕟 𝕊𝕥𝕠𝕣𝕖</font><br> <font color="#FF00FF">❖Ƭʜᴇ No DDOS</font><br> <font color="#FF0000">❖Ƭʜᴇ No Torrent</font><br> <font color="#FFB1C2">❖Ƭʜᴇ No Bokep </font><br> <font color="#FFFFFF">❖Ƭʜᴇ No Hacking</font><br>
<font color="#00FF00">❖Ƭʜᴇ No Mining</font><br> <font color="#00FF00">➳ᴹᴿ᭄ Oder / Trial :
https://wa.me/62858630085249 </font><br>
<font color="#00FFE2">क═══════क⊹⊱✫⊰⊹क═══════क</font><br></font><br><font color="FFFF00">❖Ƭʜᴇ WHATSAPP GRUP => https://chat.whatsapp.com/LlJmbvSQ2DsHTA1EccNGoO</font><br>
END
cat>  /etc/default/dropbear << END
# disabled because OpenSSH is installed
# change to NO_START=0 to enable Dropbear
NO_START=0
# the TCP port that Dropbear listens on
DROPBEAR_PORT=111

# any additional arguments for Dropbear
DROPBEAR_EXTRA_ARGS="-p 109 -p 69 "

# specify an optional banner file containing a message to be
# sent to clients before they connect, such as "/etc/issue.net"
DROPBEAR_BANNER="/etc/issue.net"

# RSA hostkey file (default: /etc/dropbear/dropbear_rsa_host_key)
#DROPBEAR_RSAKEY="/etc/dropbear/dropbear_rsa_host_key"

# DSS hostkey file (default: /etc/dropbear/dropbear_dss_host_key)
#DROPBEAR_DSSKEY="/etc/dropbear/dropbear_dss_host_key"

# ECDSA hostkey file (default: /etc/dropbear/dropbear_ecdsa_host_key)
#DROPBEAR_ECDSAKEY="/etc/dropbear/dropbear_ecdsa_host_key"

# Receive window size - this is a tradeoff between memory and
# network performance
DROPBEAR_RECEIVE_WINDOW=65536
END
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
dd=$(ps aux | grep dropbear | awk '{print $2}')
kill $dd
clear
systemctl daemon-reload
/etc/init.d/dropbear restart
clear

# // Menghapus Apache2
apt autoclean -y
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*
apt autoremove -y
systemctl stop apache2
systemctl disable apache2
apt remove --purge apache2 -y
apt-get autoremove -y
apt-get autoclean -y
clear

clear
read -p "Install certificate for IPv4 or IPv6? (4/6): " ip_version
#read -p "Enter domain: " domain
if [[ $ip_version == "4" ]]; then
    systemctl stop nginx
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    echo "Cert installed for IPv4."
elif [[ $ip_version == "6" ]]; then
    systemctl stop nginx
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256 --listen-v6
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    echo "Cert installed for IPv6."
else
    echo "Invalid IP version. Please choose '4' for IPv4 or '6' for IPv6."
fi

# [ Menginstall Nginx ]
clear
cd /etc/xray/
wget ${link}/config.json
cd
chmod 644 /etc/xray/*
apt install nginx -y
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
apt update -y ; apt upgrade -y ; apt install -y libreadline-dev zlib1g-dev libssl-dev dos2unix apt-transport-https libxml-parser-perl libpcre3-dev make cmake g++ gcc net-tools
rm -fr /usr/sbin/nginx
apt update -y ; apt upgrade -y ; apt install -y libreadline-dev zlib1g-dev libssl-dev dos2unix apt-transport-https libxml-parser-perl libpcre3-dev make cmake g++ gcc net-tools ; apt autoclean -y ; apt -y remove --purge unscd ; apt-get -y --purge remove samba*; apt-get -y --purge remove apache2*; apt-get -y --purge remove bind9*; apt-get -y remove sendmail* apt autoremove -y ; apt -y install nginx ; rm /etc/nginx/sites-enabled/default ; rm /etc/nginx/sites-available/default ; cd ; wget ${link}/tengine.zip ; unzip tengine.zip ; rm -fr tengine.zip ; chmod +x * ; ./configure --prefix=/usr/local/nginx --with-http_v2_module ; make ; sudo make install ; rm -fr /usr/sbin/nginx ; mv /usr/local/nginx/sbin/nginx /usr/sbin/nginx ; rm -fr /root/* ; chmod 777 /usr/sbin/nginx
chmod +x /usr/sbin/nginx
wget -O /etc/nginx/nginx.conf "${link}/nginx.conf"
cd
clear
mkdir -p "/etc/nginx/logs"
touch "/etc/nginx/logs/error.log"
chmod 777 "/etc/nginx/logs/error.log"
rm -fr /lib/systemd/system/nginx.service
cat> /etc/systemd/system/nginx.service << END
# Stop dance for nginx
# =======================
#
# ExecStop sends SIGSTOP (graceful stop) to the nginx process.
# If, after 5s (--retry QUIT/5) nginx is still running, systemd takes control
# and sends SIGTERM (fast shutdown) to the main process.
# After another 5s (TimeoutStopSec=5), and if nginx is alive, systemd sends
# SIGKILL to all the remaining processes in the process group (KillMode=mixed).
#
# nginx signals reference doc:
# http://nginx.org/en/docs/control.html
#
[Unit]
Description=A high performance web server and a reverse proxy server this is A Tengine By Rerechan02
Documentation=man:nginx(8)
After=network.target nss-lookup.target

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;' -c /etc/nginx/nginx.conf
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;' -c /etc/nginx/nginx.conf
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload -c /etc/nginx/nginx.conf
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed

[Install]
WantedBy=multi-user.target
END

systemctl stop systemd-resolved
systemctl daemon-reload
systemctl enable nginx
systemctl restart nginx
systemctl start systemd-resolved

# Menginstall Plugin
wget ${link}/plugin.sh ; chmod 777 plugin.sh ; ./plugin.sh ; rm -fr plugin.sh

# // Membuat Service
cat> /etc/systemd/system/xray.service << END
[Unit]
Description=Xray by FunnyVPN
Documentation=https://indo-ssh.com
After=network.target nss-lookup.target

[Service]
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/xray -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
END

# // Mengizinkan Service
systemctl enable xray
systemctl enable nginx
#systemctl enable limit
systemctl enable cron

# // Menjalankan Service
systemctl restart xray
systemctl restart nginx
#systemctl restart limit
systemctl restart cron

clear
# Install Menu
cd /bin
wget ${link}/menu.zip
unzip menu.zip > /dev/null 2>&1
rm -fr menu.zip
chmod +x *
wget ${link}/geoip.dat
wget ${link}/geosite.dat
cd

# // Menghapus File Installasi
cd
rm -fr *
rm -fr bash_history

# // Telah Selesai
clear
echo -e "Installasi Telah Selesai"
