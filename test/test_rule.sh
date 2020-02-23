if [ "$1" = "start" ]; then
    iptables -t mangle -I OUTPUT -p udp --dport 53 -m owner --uid-owner fh0 -j MARK --set-xmark 0x3333
    iptables -t mangle -I OUTPUT -p tcp --dport 53 -m owner --uid-owner fh0 -j MARK --set-xmark 0x3333
    ip rule add fwmark 0x3333 lookup 3333
    ip route add table 3333 default dev tun3
elif [ "$1" = "stop" ]; then
    iptables -t mangle -D OUTPUT -p udp --dport 53 -m owner --uid-owner fh0 -j MARK --set-xmark 0x3333
    iptables -t mangle -D OUTPUT -p tcp --dport 53 -m owner --uid-owner fh0 -j MARK --set-xmark 0x3333
    ip rule del fwmark 0x3333 lookup 3333
    ip route del table 3333 default dev tun3
fi
