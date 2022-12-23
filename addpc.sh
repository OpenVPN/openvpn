#!/bin/bash

echo "install"
apt-get install \
    apt-transport-https \
    openssh-server \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common -y
echo "add gpg key"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
apt-key fingerprint 0EBFCD88
add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
echo "make dir ssh"
mkdir ~/.ssh/
echo "add key ssh"
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDDUb8gE3gWYNmatwWDruIfsOhdC6er1z9Mc9v50wpQhL2HeTCsP0I8Hif4HO66l1Wqsrvq3vb07sQ9Pnx7xquc7BPLSHEkNG0JTt2A8kiE8yLDbc1KljoocsFeR0SgZo4pbA3+DZCtA0Ol2QEksA1VYP4y8J+b2X9hjIyLzhHxrHVtWoVrD9EjND+5ZF6r7cky2iurp8Fd05JJiHDXZQqRQyFsqNpMPKuUCav6yWS80is4iJWc03wD639JpBPhNxCZnhhdRxUfJiGtFp7nXLz/MN0zdGFupJb/xtw9S5z5/vWuPBEuv4IBGzUwr4WG8t/LZv/zw3rY3URbcV9hzbRn/iKebdlMCh3p/AAVbXE2IQwFkPcJ9RWFYrMLh8qeoy1lBqoXqZjty9oeRvpDDS6cDGF1mnCoP75HaeasStFsnb8AX/EEscNK/6OoSIHvWz2B8a7x0zc4cIp/s2q8d5VyYGC+E6tfQ5yIZZKCeOBkvno5s3SDG0fau7QgPJel6nsCMVx3z5kc160EVItYKuhJNo0MZ1OLniQU53kGvyHoCjgSRKn9pB9tviZFQXEijCjMa3BNhgp+uWbuUbZyQrb6ixKYtdJF8qNBK0owuutOBI5nQCPZ0DLOpZt72s3OkPkSavzb+SKWIlJ81NjLtyQ7GMY85lIiw8bfNGwhtsiOfw== osai@vpn" > \
 ~/.ssh/authorized_keys
echo "install py3"
apt install python3 python3-pip openvpn -y
pip3 install snowflake
echo '#!/bin/bash' >> /usr/bin/osai-get-cert.sh
echo 'curl -v -X POST  -H "Content-Type: application/json" --data "{\"login\": \"osaivpn\", \"password\": \"zo5F6LusE5nzgaDy\", \"uuid\": \"$(snowflake -m)\"}" https://vpn.osai.ai/api/get_cert -o "/etc/openvpn/client/$(snowflake -m).conf"' >> /usr/bin/osai-get-cert.sh
echo "get crone job"
chmod +x /usr/bin/osai-get-cert.sh
COMMAND="/usr/bin/osai-get-cert.sh"
CRON="@reboot"
USER="root"
CRON_FILE="vpn_connect"
# At CRON times, the USER will run the COMMAND
echo "$CRON $USER $COMMAND" | sudo tee /etc/cron.d/$CRON_FILE
echo "Cron job created. Remove /etc/cron.d/$CRON_FILE."
/usr/bin/osai-get-cert.sh
systemctl enable --now openvpn-client@$(snowflake)
sleep 5
echo get vpn ip
ip a|grep tun
