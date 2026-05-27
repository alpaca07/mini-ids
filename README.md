# Mini IDS (침입 탐지 시스템)

# 개요
Python + Scapy로 구현한 네트워크 침입 탐지 시스템.
포트 스캔과 ICMP Flood를 실시간 탐지하고 웹 대시보드로 시각화.

# 탐지 기능
| 공격 유형 | 탐지 기준 | 방법 |
|----------|----------|------|
| 포트 스캔 | 10초 내 5개 이상 포트에 SYN 패킷 | TCP 플래그 분석 |
| DDoS (ICMP Flood) | 1초 내 ICMP 100개 이상 | 패킷 카운팅 |

# 기술 스택
- Python 3, Scapy, Flask
- Ubuntu 22.04 (VirtualBox VM)

# 실행 방법
# 탐지 엔진 실행
sudo python3 detector.py

# 대시보드 실행
python3 dashboard.py


# 프로젝트 구조
'''
mini-ids/
├── capture.py      # 패킷 캡처 및 CSV 저장
├── detector.py     # 포트 스캔 / DDoS 탐지 엔진
├── dashboard.py    # Flask 웹 대시보드
└── .gitignore
'''

## 배운 점
- TCP 3-way handshake와 SYN 플래그 동작 원리
- DNS가 UDP → TCP로 전환되는 과정을 실트래픽으로 직접 확인
- 규칙 기반 탐지(Rule-based Detection)의 구현과 한계
- .gitignore로 민감한 로그 데이터 GitHub 업로드 방지
