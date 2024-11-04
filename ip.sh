iptables -t mangle -A PREROUTING -i tailscale0 -m mark --mark 0x0/0x18 -j CONNMARK --restore-mark --nfmask 0x18 --ctmask 0x18
iptables -t mangle -A PREROUTING -i tailscale0 -p tcp -m mark --mark 0x0/0x10 -m tcp --dport 443 --tcp-flags FIN,SYN,RST,PSH,ACK,URG SYN -j NFQUEUE --queue-num 123 --queue-bypass
iptables -t mangle -A PREROUTING -i tailscale0 -p tcp -m tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK ACK -m mark --mark 0x0/0x10 -j NFQUEUE --queue-num 123 --queue-bypass
iptables -t mangle -A PREROUTING -i tailscale0 -j CONNMARK --save-mark --nfmask 0x18 --ctmask 0x18


iptables -t mangle -A OUTPUT -m mark --mark 0x0/0x18 -j CONNMARK --restore-mark --nfmask 0x18 --ctmask 0x18
iptables -t mangle -A OUTPUT -p tcp -m mark --mark 0x0/0x10 -m tcp --dport 443 --tcp-flags FIN,SYN,RST,PSH,ACK,URG SYN -j NFQUEUE --queue-num 123 --queue-bypass
iptables -t mangle -A OUTPUT -p tcp -m tcp --dport 443 --tcp-flags FIN,SYN,RST,ACK ACK -m mark --mark 0x0/0x10 -j NFQUEUE --queue-num 123 --queue-bypass
iptables -t mangle -A OUTPUT -j CONNMARK --save-mark --nfmask 0x18 --ctmask 0x18

