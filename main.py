#!/usr/bin/env python3

import dpkt
from time import time

flag = "testing_testing_123"

def handshake(src_ip, src_port, dst_ip, dst_port):
    pkt_syn = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP()
    ip.src = src_ip
    ip.dst = dst_ip
    ip.p = 6
    tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port, flags=dpkt.tcp.TH_SYN, seq=0)
    ip.data = tcp
    ip.len += len(ip.data)
    pkt_syn.data = ip

    pkt_syn_ack = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP()
    ip.src = dst_ip
    ip.dst = src_ip
    ip.p = 6
    tcp = dpkt.tcp.TCP(sport=dst_port, dport=src_port, flags=(dpkt.tcp.TH_SYN |dpkt.tcp.TH_ACK), seq=0, ack=1)
    ip.data = tcp
    ip.len += len(ip.data)
    pkt_syn_ack.data = ip

    pkt_ack = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP()
    ip.src = src_ip
    ip.dst = dst_ip
    ip.p = 6
    tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port, flags=dpkt.tcp.TH_ACK, seq=1, ack=1)
    ip.data = tcp
    ip.len += len(ip.data)
    pkt_ack.data = ip

    return [(time(), bytes(pkt_syn)), (time(), bytes(pkt_syn_ack)), (time(), bytes(pkt_ack))]

def fin_handshake(src_ip, src_port, dst_ip, dst_port, seq, ack):
    pkt_fin_ack_src = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP()
    ip.src = src_ip
    ip.dst = dst_ip
    ip.p = 6
    tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port, flags=(dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK), seq=seq, ack=ack)
    ip.data = tcp
    ip.len += len(ip.data)
    pkt_fin_ack_src.data = ip

    pkt_fin_ack_dst = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP()
    ip.src = dst_ip
    ip.dst = src_ip
    ip.p = 6
    tcp = dpkt.tcp.TCP(sport=dst_port, dport=src_port, flags=(dpkt.tcp.TH_FIN | dpkt.tcp.TH_ACK), seq=ack, ack=seq+1)
    ip.data = tcp
    ip.len += len(ip.data)
    pkt_fin_ack_dst.data = ip

    pkt_ack_src = dpkt.ethernet.Ethernet()
    ip = dpkt.ip.IP()
    ip.src = src_ip
    ip.dst = dst_ip
    ip.p = 6
    tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port, flags=dpkt.tcp.TH_ACK, seq=seq+1, ack=ack+1)
    ip.data = tcp
    ip.len += len(ip.data)
    pkt_ack_src.data = ip
    
    return [(time(), bytes(pkt_fin_ack_src)), (time(), bytes(pkt_fin_ack_dst)), (time(), bytes(pkt_ack_src))]


def main():
    with open("/app/output.pcapng", 'wb') as output:
        pcap = dpkt.pcapng.Writer(output)
        src = b'\x08\x08\x08\x08'
        dst = b'\x7f\x00\x00\x01'
        src_p = 9832
        dst_p = 1234
        pcap.writepkts(handshake(src, src_p, dst, dst_p))
        
        send = True
        delta = 0
        for i in range(2*len(flag)):
            pkt = dpkt.ethernet.Ethernet()
            ip = dpkt.ip.IP()
            if (send):
                ip.src = src
                ip.dst = dst
                ip.p = 6
                tcp = dpkt.tcp.TCP(sport=src_p,dport=dst_p,seq=1+delta,ack=1,flags=(dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK))
                tcp.data = flag[i//2].encode('utf-8')
                delta += len(tcp.data)
                ip.data = tcp
                send = False
            else:
                ip.src = dst
                ip.dst = src
                ip.p = 6
                tcp = dpkt.tcp.TCP(sport=dst_p,dport=src_p,seq=1,ack=1+delta,flags=(dpkt.tcp.TH_ACK))
                ip.data = tcp
                send = True
            ip.len += len(ip.data)
            pkt.data = ip
            pcap.writepkt(bytes(pkt))

        pcap.writepkts(fin_handshake(src, src_p, dst, dst_p, 1+delta, 1))

if __name__ == "__main__":
    main()
