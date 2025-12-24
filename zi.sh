#!/bin/bash
# Zivpn UDP Module installer
# Creator Zahid Islam
# Modified to include persistent iptables and sysctl optimizations

# Mendeteksi Interface Jaringan Utama
NIC=$(ip -4 route ls|grep default|grep -Po '(?<=dev )(\S+)'|head -1)

echo -e "Updating server & Installing Dependencies"
# Menyiapkan jawaban otomatis untuk iptables-persistent sebelum instalasi
sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
sudo debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"

# Update dan install paket yang dibutuhkan (termasuk iptables-persistent)
sudo apt-get update && apt-get upgrade -y
sudo apt-get install -y iptables-persistent netfilter-persistent wget

systemctl stop zivpn.service 1> /dev/null 2> /dev/null

echo -e "Downloading UDP Service"
wget https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64 -O /usr/local/bin/zivpn 1> /dev/null 2> /dev/null
chmod +x /usr/local/bin/zivpn
mkdir /etc/zivpn 1> /dev/null 2> /dev/null
wget https://raw.githubusercontent.com/zahidbd2/udp-zivpn/main/config.json -O /etc/zivpn/config.json 1> /dev/null 2> /dev/null

echo "Generating cert files:"
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" -keyout "/etc/zivpn/zivpn.key" -out "/etc/zivpn/zivpn.crt"

# Tweak buffer memory
sysctl -w net.core.rmem_max=16777216 1> /dev/null 2> /dev/null
sysctl -w net.core.wmem_max=16777216 1> /dev/null 2> /dev/null

# Membuat Service Systemd
cat <<EOF > /etc/systemd/system/zivpn.service
[Unit]
Description=zivpn VPN Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/zivpn/config.json
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

echo -e "ZIVPN UDP Passwords"
read -p "Enter passwords separated by commas, example: pass1,pass2 (Press enter for Default 'zi'): " input_config

if [ -n "$input_config" ]; then
    IFS=',' read -r -a config <<< "$input_config"
    if [ ${#config[@]} -eq 1 ]; then
        config+=(${config[0]})
    fi
else
    config=("zi")
fi

new_config_str="\"config\": [$(printf "\"%s\"," "${config[@]}" | sed 's/,$//')]"

sed -i -E "s/\"config\": ?\[[[:space:]]*\"zi\"[[:space:]]*\]/${new_config_str}/g" /etc/zivpn/config.json

systemctl enable zivpn.service
systemctl start zivpn.service

# Menerapkan Aturan IPTables
iptables -t nat -A PREROUTING -i $NIC -p udp --dport 6000:19999 -j DNAT --to-destination :5667
ufw allow 6000:19999/udp
ufw allow 5667/udp

# --- BAGIAN TAMBAHAN (SYSCTL & PERSISTENCE) ---
echo -e "Applying Network Optimizations..."

# Mengaktifkan IP Forwarding & Mematikan RP Filter secara langsung
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.$NIC.rp_filter=0
sysctl -w net.ipv4.ip_forward=1

# Menulis konfigurasi ke /etc/sysctl.conf agar permanen setelah reboot
# Menggunakan 'tee -a' untuk append (menambahkan) agar tidak menimpa isi file yang sudah ada, atau '>' untuk replace.
# Di sini saya menggunakan logika replace parsial atau append yang aman.
cat <<EOF >> /etc/sysctl.conf
net.ipv4.ip_forward = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.$NIC.rp_filter = 0
EOF

# Reload sysctl
sysctl -p

# Menyimpan aturan IPtables
echo -e "Saving IPtables rules..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6
netfilter-persistent save
netfilter-persistent reload

# --- AKHIR BAGIAN TAMBAHAN ---

rm zi.* 1> /dev/null 2> /dev/null
echo -e "ZIVPN UDP Installed and Optimized"
