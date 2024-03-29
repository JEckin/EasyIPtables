#!/bin/bash

main(){
clear
echo "++==============================================================================================++"
echo "||                                                                                              ||"
echo "|| ███████╗ █████╗ ███████╗██╗   ██╗██╗██████╗ ████████╗ █████╗ ██████╗ ██╗     ███████╗███████╗||"
echo "|| ██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██║██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██║     ██╔════╝██╔════╝||"
echo "|| █████╗  ███████║███████╗ ╚████╔╝ ██║██████╔╝   ██║   ███████║██████╔╝██║     █████╗  ███████╗||"
echo "|| ██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██║██╔═══╝    ██║   ██╔══██║██╔══██╗██║     ██╔══╝  ╚════██║||"
echo "|| ███████╗██║  ██║███████║   ██║   ██║██║        ██║   ██║  ██║██████╔╝███████╗███████╗███████║||"
echo "|| ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝╚═╝        ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝||"
echo "||                                                                                              ||"
echo "++==============================================================================================++"
echo""
echo "01] List 		02] Security configuration"
echo "03] Table Filter	04] Table NAT"
echo "05] Table Mangle	06] Table RAW"
echo "07] Table Security"
echo "98] Update/Installation	99] Exit"
read start
case "$start" in
01 | 1)
list
;;
02 | 2)
security
;;
03 | 3)
tf
;;
04 | 4)
tn
;;
05 | 5)
tm
;;
06 | 6)
tr
;;
07 | 7)
ts
;;
98)
clear
update
;;
99)
clear
exit
exit="true"
;;
esac
}

tn(){
clear
echo "1]"
}

tfcreate() {
clear
echo "1] Add source rule to Chain"
echo "2] Add input/output rule to Chain"
echo "3] Add Port rule to Chain"
read tfcreate
case "$tfcreate" in
1)
clear
ip addr
echo "IP address:"
read ip
clear
iptables -vL -t filter
echo "==============="
echo "Chain (case-sensitive):"
read chain
clear
echo "1] Accept"
echo "2] Drop"
echo "3] Return"
read a
if [ $a == 1 ]; then
do="ACCEPT"
elif [ $a == 2 ]; then
do="DROP"
elif [ $a == 3 ]; then
do="RETURN"
fi
iptables -A $chain -s $ip -j $do
;;
2)
clear
ip addr
echo "Interface:"
read face
clear
echo "1] Input"
echo "2] Output"
read v
if [ $v == 1 ]
then
put="-o"
chain=OUTPUT
else
put="-i"
chain=INPUT
fi
clear
echo "1] Accept"
echo "2] Drop"
echo "3] Return"
read a
if [ $a == 1 ]; then
do="ACCEPT"
elif [ $a == 2 ]; then
do="DROP"
elif [ $a == 3 ]; then
do="RETURN"
fi
iptables -A $chain $put $face -j $do
;;
3)
clear
ip addr
echo "=========="
echo "Interface:"
read face
clear
echo "1] Incomming (Input)"
echo "2] Outgoing (Output)"
read v
if [ $v == 2 ]
then
put="-o"
chain=OUTPUT
else
put="-i"
chain=INPUT
fi
clear
echo "Port:"
read port
clear
echo "1] TCP"
echo "2] UDP"
read tcpudp
if [ $tcpudp = 2 ]; then
tcpudp="udp"
else
tcpudp="tcp"
fi
clear
echo "1] Accept"
echo "2] Drop"
echo "3] Return"
read a
if [ $a == 1 ]; then
do="ACCEPT"
elif [ $a == 2 ]; then
do="DROP"
elif [ $a == 3 ]; then
do="RETURN"
fi
iptables -A $chain $put $face -p $tcpudp --dport $port --sport 1024:65535 -j $do
clear
list 1
;;
esac
tf
}

tf() {
clear
echo " 1] list rules"
echo " 2] Change Policy from a Chain"
echo " 3] Create rules"
echo " 4] Delete rules"
echo " 5] Create chain"
echo " 6] Delete chain with rules"
echo " 7] Flush chain"
echo " 8] Flush table"
echo "99] Back"
read tf
case "$tf" in
1)
list 1
tf
;;
2)
clear
iptables -vL -t filter
echo "==============="
echo "Chain (case-sensitive):"
read chain
clear
echo "1] Accept"
echo "2] Drop"
read a
if [ $a == 1 ]; then
do="ACCEPT"
elif [ $a == 2 ]; then
do="DROP"
fi
iptables -P $chain $do
;;
3)
tfcreate
;;
4)
clear
iptables -vL -t filter
echo "================"
echo "Chain (case-sensitive):"
read chain
echo "Position (row):"
read row
iptables -D $chain $row
;;
5)
clear
echo "Chain:"
read chain
if [ $chain ]
then
iptables -N $chain
list 1
fi
;;
6)
clear
iptables -vL -t filter
echo "==============="
echo "Chain (case-sensitive):"
read chain
if [ $chain ]
then
iptables -X $chain
list 1
fi
;;
7)
clear
iptables -vL -t filter
echo "================"
echo "Chain (case-sensitive):"
read chain
if [ $chain ]
then
iptables -F $chain -t filter
list 1
fi
;;
8)
iptables -F -t filter
list 1
;;
99)
echo ""
;;
esac
}

update() {
clear
git clone https://github.com/jeckin/easyiptables /tmp/easyiptables
cp /tmp/easyiptables/easyiptables.sh /bin/eip
cp /tmp/easyiptables/easyiptables.sh /bin/easyiptables
sudo chmod +x /bin/eip
sudo chmod +x /bin/easyiptables
rm -r /tmp/easyiptables
exit="true"
}

list() {
clear
if [ ! $1 ]
then
echo "1] Filter rules"
echo "2] NAT rules"
echo "3] Mangle rules"
echo "4] Raw rules"
echo "5] Security rules"
read list
else
list=$1
fi
case "$list" in
1)
clear
iptables -vL -t filter > /tmp/table
cat /tmp/table | less
;;
2)
clear
iptables -vL -t nat > /tmp/table
cat /tmp/table | less
;;
3)
clear
iptables -vL -t mangle > /tmp/table
cat /tmp/table | less
;;
4)
clear
iptables -vL -t raw > /tmp/table
cat /tmp/table | less
;;
5)
clear
iptables -vL -t security > /tmp/table
cat /tmp/table | less
;;
esac
if [ -f /tmp/table ]
then
rm /tmp/table
fi
}

security() {
clear
ip addr
echo "=================="
echo "Interface:"
read net
clear
echo "Slow down ICMP at too many packages (y/N)"
read s
if [ $s = "y" ]
then
echo "5" > /proc/sys/net/ipv4/icmp_ratelimit
fi
clear
s=""
echo "Kill packages with the source route option (y/N)"
read s
if [ $s = "y" ]
then
echo "0">/proc/sys/net/ipv4/conf/$net/accept_source_route
fi
clear
s=""
echo "Kill ICMP forwarding (y/N)"
read s
if [ $s = "y" ]
then
echo "0">/proc/sys/net/ipv4/conf/$net/accept_redirects
fi
clear
s=""
echo "Allways defragment IP-packeges (y/N)"
read s
if [ $s = "y" ]
then
echo "1">/proc/sys/net/ipv4/conf/$net/ip_always_defrag
fi
clear
s=""
echo "Kill spoofed packages (y/N)"
read s
if [ $s = "y" ]
then
echo "1" > /proc/sys/net/ipv4/conf/$net/rp_filter
fi
clear
s=""
echo "Kill packages from 0.X.X.X (y/N)"
read s
if [ $s = "y" ]
then
echo "0" > /proc/sys/net/ipv4/conf/eth0/bootp_relay
fi
clear
s=""
echo "TCP-FIN-Timeout for DoS-Attacks (y/N)"
read s
if [ $s = "y" ]
then
echo 30 > /proc/sys/net/ipv4/tcp_fin_timeout
fi
clear
s=""
echo "Maximal 3 replys for a TCP-SYN (y/N)"
read s
if [ $s = "y" ]
then
echo 3 > /proc/sys/net/ipv4/tcp_retries1
fi
clear
s=""
echo "Maximal 15 retrys for TCP-packages (y/N)"
read s
if [ $s = "y" ]
then
echo 15 > /proc/sys/net/ipv4/tcp_retries2
fi
}


exit="false"
while [ $exit=="false" ]
do
main
done

