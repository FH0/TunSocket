
iptables -t mangle -D OUTPUT -m connmark --mark 0x3333 -j CONNMARK --restore-mark
# iptables -t mangle -D OUTPUT -p udp -m owner --uid-owner fh0 -j CONNMARK --set-xmark 0x3333
iptables -t mangle -D OUTPUT -p tcp -m owner --uid-owner fh0 -j CONNMARK --set-xmark 0x3333
ip rule del fwmark 0x3333 lookup 3333
ip route del table 3333 default dev tun3

if [ "$1" = "start" ]; then
    iptables -t mangle -I OUTPUT -m connmark --mark 0x3333 -j CONNMARK --restore-mark
    #iptables -t mangle -I OUTPUT -p udp -m owner --uid-owner fh0 -j CONNMARK --set-xmark 0x3333
    iptables -t mangle -I OUTPUT -p tcp -m owner --uid-owner fh0 -j CONNMARK --set-xmark 0x3333
    ip rule add fwmark 0x3333 lookup 3333
    ip route add table 3333 default dev tun3
fi
