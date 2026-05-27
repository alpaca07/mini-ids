from scapy.all import sniff, IP, TCP, UDP, ICMP
import csv
import datetime

# CSV 파일 준비
csvfile = open('packets.csv', 'w', newline='')
writer = csv.writer(csvfile)
writer.writerow(['time', 'protocol', 'src_ip', 'src_port', 'dst_ip', 'dst_port'])

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        now = datetime.datetime.now().strftime('%H:%M:%S')
        src_port = dst_port = '-'

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        else:
            return  # TCP/UDP/ICMP 외 무시

        print(f"[{protocol}] {src_ip}:{src_port} → {dst_ip}:{dst_port}")
        writer.writerow([now, protocol, src_ip, src_port, dst_ip, dst_port])
        csvfile.flush()  # 바로바로 파일에 저장

sniff(iface="ens33", prn=packet_handler, store=False)
