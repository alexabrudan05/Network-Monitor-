Real-time network monitoring dashboard built with Python + Streamlit.

## Features
- Live bandwidth tracking (RX/TX) in MB/s
- Latency monitoring to 8.8.8.8 and 1.1.1.1
- Network interface overview
- Active TCP connections list
- Auto-refreshing dashboard

## Setup

```bash
pip install -r requirements.txt
streamlit run app.py
```

It opens http://localhost:8501 in your browser

## Tech Stack
- `psutil` - network I/O, interfaces, connections
- `ping3` - ICMP latency measurement  
- `streamlit` - web UI
- `plotly` - interactive charts
