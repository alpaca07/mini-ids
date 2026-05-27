from flask import Flask, render_template_string
import datetime

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <title>Mini IDS Dashboard</title>
  <style>
    body { background: #0d1117; color: #c9d1d9; font-family: monospace; padding: 2rem; }
    h1 { color: #58a6ff; }
    .stat { display: inline-block; background: #161b22; border: 1px solid #30363d;
            border-radius: 8px; padding: 1rem 2rem; margin: 0.5rem; text-align: center; }
    .stat .num { font-size: 2rem; font-weight: bold; color: #f85149; }
    .stat .label { font-size: 0.8rem; color: #8b949e; }
    table { width: 100%; border-collapse: collapse; margin-top: 1.5rem; }
    th { background: #161b22; color: #58a6ff; padding: 0.6rem 1rem; text-align: left; }
    td { padding: 0.6rem 1rem; border-bottom: 1px solid #21262d; }
    tr:hover { background: #161b22; }
    .portscan { color: #ffa657; }
    .ddos { color: #f85149; }
  </style>
</head>
<body>
  <h1>🛡️ Mini IDS Dashboard</h1>
  <p style="color:#8b949e">{{ now }} | 5초마다 자동 갱신</p>

  <div>
    <div class="stat">
      <div class="num">{{ total }}</div>
      <div class="label">전체 탐지</div>
    </div>
    <div class="stat">
      <div class="num" style="color:#ffa657">{{ portscan }}</div>
      <div class="label">포트 스캔</div>
    </div>
    <div class="stat">
      <div class="num">{{ ddos }}</div>
      <div class="label">DDoS 의심</div>
    </div>
  </div>

  <table>
    <tr><th>시간</th><th>유형</th><th>내용</th></tr>
    {% for row in logs %}
    <tr>
      <td>{{ row.time }}</td>
      <td class="{{ row.type }}">{{ row.type }}</td>
      <td>{{ row.msg }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
"""

def parse_logs():
    logs = []
    portscan = 0
    ddos = 0
    try:
        with open('ids_log.txt', 'r') as f:
            for line in f.readlines()[-50:]:  # 최근 50개만
                if '포트 스캔' in line:
                    t = line[1:20]
                    msg = line[22:].strip()
                    logs.append({'time': t, 'type': 'portscan', 'msg': msg})
                    portscan += 1
                elif 'DDoS' in line:
                    t = line[1:20]
                    msg = line[22:].strip()
                    logs.append({'time': t, 'type': 'ddos', 'msg': msg})
                    ddos += 1
    except FileNotFoundError:
        pass
    logs.reverse()  # 최신순
    return logs, portscan, ddos

@app.route('/')
def index():
    logs, portscan, ddos = parse_logs()
    return render_template_string(HTML,
        logs=logs,
        total=len(logs),
        portscan=portscan,
        ddos=ddos,
        now=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
