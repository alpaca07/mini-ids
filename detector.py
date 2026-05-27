from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import datetime

# 로그 파일 준비
logfile = open('ids_log.txt', 'a')

def log(msg):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f"[{timestamp}] {msg}"
    print(line)
    logfile.write(line + '\n')
    logfile.flush()

# ──────────────────────────────
# 포트 스캔 탐지용
scan_tracker = defaultdict(set)
scan_first_seen = {}
SCAN_THRESHOLD = 5
SCAN_WINDOW = 10

# DDoS 탐지용 (단위 시간당 패킷 수)
ddos_tracker = defaultdict(int)
ddos_first_seen = {}
DDOS_THRESHOLD = 100   # 초당 패킷 수
DDOS_WINDOW = 1        # 1초 기준

def detect(packet):
    if not IP in packet:
        return

    src_ip = packet[IP].src
    now = datetime.datetime.now()

    # ── 포트 스캔 탐지 ──
    if TCP in packet and packet[TCP].flags == 0x02:
        dst_port = packet[TCP].dport

        if src_ip not in scan_first_seen:
            scan_first_seen[src_ip] = now

        if (now - scan_first_seen[src_ip]).seconds > SCAN_WINDOW:
            scan_tracker[src_ip].clear()
            scan_first_seen[src_ip] = now

        scan_tracker[src_ip].add(dst_port)

        if len(scan_tracker[src_ip]) >= SCAN_THRESHOLD:
            log(f"🚨 [포트 스캔] 공격자: {src_ip} | 포트: {sorted(scan_tracker[src_ip])}")
            scan_tracker[src_ip].clear()
            scan_first_seen[src_ip] = now

    # ── DDoS 탐지 (ICMP Flood) ──
    if ICMP in packet:
        if src_ip not in ddos_first_seen:
            ddos_first_seen[src_ip] = now

        if (now - ddos_first_seen[src_ip]).seconds > DDOS_WINDOW:
            ddos_tracker[src_ip] = 0
            ddos_first_seen[src_ip] = now

        ddos_tracker[src_ip] += 1

        if ddos_tracker[src_ip] >= DDOS_THRESHOLD:
            log(f"🚨 [DDoS 의심] 공격자: {src_ip} | {DDOS_WINDOW}초간 {ddos_tracker[src_ip]}개 ICMP 패킷")
            ddos_tracker[src_ip] = 0
            ddos_first_seen[src_ip] = now

sniff(iface="lo", prn=detect, store=False)
