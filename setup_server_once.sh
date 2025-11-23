# enable ipv4 forwarding
sysctl -w net.ipv4.ip_forward=1

# set ssh session alive for 60 min
sed -i \
    -e '/^ClientAliveInterval/d' \
    -e '/^ClientAliveCountMax/d' \
    -e '$a ClientAliveInterval 60' \
    -e '$a ClientAliveCountMax 3' \
    /etc/ssh/sshd_config

systemctl reload ssh