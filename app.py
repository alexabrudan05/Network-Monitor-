import streamlit as st
import psutil
import time
import plotly.graph_objects as go
from plotly.subplots import make_subplots
from collections import deque
from datetime import datetime
import socket
import threading
import json
import os
import tempfile

try:
    from ping3 import ping
    PING3_AVAILABLE = True
except ImportError:
    PING3_AVAILABLE = False


PING_TARGETS = {
    "8.8.8.8 (Google DNS)": "8.8.8.8",
    "1.1.1.1 (Cloudflare)": "1.1.1.1",
}
HISTORY_LEN = 60          # seconds of history shown in graphs
REFRESH_MS  = 2000        # auto-refresh interval

st.set_page_config(
    page_title="Network Monitor",
    page_icon="📡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# Css section
st.markdown("""
<style>
    /* compact header */
    .block-container { padding-top: 1.2rem; padding-bottom: 1rem; }
    h1 { margin-bottom: 0.2rem; }
    /* metric cards */
    [data-testid="metric-container"] {
        background: #1e1e2e;
        border: 1px solid #2a2a3e;
        border-radius: 10px;
        padding: 12px 16px;
    }
    [data-testid="metric-container"] label { color: #9399b2 !important; font-size: 0.78rem; }
    [data-testid="metric-container"] [data-testid="stMetricValue"] { font-size: 1.4rem; font-weight: 700; }
    /* status badges */
    .badge-ok   { background:#1a3a2a; color:#4ade80; padding:3px 10px; border-radius:12px; font-size:0.82rem; font-weight:600; }
    .badge-warn { background:#3a2a10; color:#fb923c; padding:3px 10px; border-radius:12px; font-size:0.82rem; font-weight:600; }
    .badge-err  { background:#3a1a1a; color:#f87171; padding:3px 10px; border-radius:12px; font-size:0.82rem; font-weight:600; }
    /* section headers */
    .section-title { font-size:0.72rem; font-weight:700; letter-spacing:0.12em; color:#9399b2; text-transform:uppercase; margin:1rem 0 0.5rem; }
    /* hide streamlit branding */
    #MainMenu, footer { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

from streamlit_autorefresh import st_autorefresh
st_autorefresh(interval=REFRESH_MS, key="netmon_autorefresh")

def _init_state():
    if "timestamps"    not in st.session_state:
        st.session_state.timestamps    = deque(maxlen=HISTORY_LEN)
    if "rx_history"    not in st.session_state:
        st.session_state.rx_history    = deque(maxlen=HISTORY_LEN)
    if "tx_history"    not in st.session_state:
        st.session_state.tx_history    = deque(maxlen=HISTORY_LEN)
    if "ping_history"  not in st.session_state:
        st.session_state.ping_history  = {k: deque(maxlen=HISTORY_LEN) for k in PING_TARGETS}


_init_state()

_SNAP_FILE = os.path.join(tempfile.gettempdir(), "netmon_snapshot.json")

def _read_snapshot():
    try:
        with open(_SNAP_FILE) as f:
            d = json.load(f)
            return d["bytes_recv"], d["bytes_sent"], d["ts"]
    except Exception:
        return None, None, None

def _write_snapshot(recv, sent, ts):
    try:
        with open(_SNAP_FILE, "w") as f:
            json.dump({"bytes_recv": recv, "bytes_sent": sent, "ts": ts}, f)
    except Exception:
        pass

_HIST_FILE = os.path.join(tempfile.gettempdir(), "netmon_history.json")

def _read_history():
    try:
        with open(_HIST_FILE) as f:
            d = json.load(f)
            return d["ts"], d["rx"], d["tx"]
    except Exception:
        return [], [], []

def _write_history(ts, rx, tx):
    try:
        with open(_HIST_FILE, "w") as f:
            json.dump({"ts": list(ts)[-HISTORY_LEN:], "rx": list(rx)[-HISTORY_LEN:], "tx": list(tx)[-HISTORY_LEN:]}, f)
    except Exception:
        pass

def _get_main_iface():
    per_nic = psutil.net_io_counters(pernic=True)
    if "en0" in per_nic:
        return "en0"
    return max(per_nic.items(), key=lambda x: x[1].bytes_recv)[0]

MAIN_IFACE = _get_main_iface()

# Data helpers
def get_bandwidth_mbps():
    """Return (rx_mbps, tx_mbps) for main interface (en0) only."""
    now     = time.time()
    per_nic = psutil.net_io_counters(pernic=True)
    iface   = per_nic.get(MAIN_IFACE)
    if iface is None:
        return 0.0, 0.0

    curr_recv, curr_sent = iface.bytes_recv, iface.bytes_sent
    prev_recv, prev_sent, prev_ts = _read_snapshot()

    if prev_ts is None:
        _write_snapshot(curr_recv, curr_sent, now)
        return 0.0, 0.0

    dt = now - prev_ts
    if dt < 0.1:
        dt = 0.1

    rx = (curr_recv - prev_recv) / dt / 1_048_576
    tx = (curr_sent - prev_sent) / dt / 1_048_576

    _write_snapshot(curr_recv, curr_sent, now)
    return max(rx, 0.0), max(tx, 0.0)

def get_ping_ms(host: str) -> float | None:
    """Return ping in ms, or None on failure."""
    if PING3_AVAILABLE:
        try:
            result = ping(host, timeout=2, unit="ms")
            return round(result, 1) if result else None
        except Exception:
            pass
    # fallback: TCP connect to port 80
    try:
        t0 = time.perf_counter()
        with socket.create_connection((host, 53), timeout=2):
            pass
        return round((time.perf_counter() - t0) * 1000, 1)
    except Exception:
        return None

def get_top_connections(n=8):
    """Return list of dicts for active TCP connections."""
    rows = []
    seen = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.status not in ("ESTABLISHED", "LISTEN"):
                continue
            if not conn.raddr:
                continue
            key = (conn.laddr, conn.raddr)
            if key in seen:
                continue
            seen.add(key)
            try:
                proc = psutil.Process(conn.pid).name() if conn.pid else "—"
            except Exception:
                proc = "—"
            rows.append({
                "Process": proc,
                "Local": f"{conn.laddr.ip}:{conn.laddr.port}",
                "Remote": f"{conn.raddr.ip}:{conn.raddr.port}",
                "Status": conn.status,
            })
            if len(rows) >= n:
                break
    except Exception:
        pass
    return rows

def fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

def ping_badge(ms):
    if ms is None:
        return '<span class="badge-err">Timeout</span>'
    if ms < 50:
        return f'<span class="badge-ok">🟢 {ms} ms</span>'
    if ms < 150:
        return f'<span class="badge-warn">🟡 {ms} ms</span>'
    return f'<span class="badge-err">🔴 {ms} ms</span>'

#  Collect tick's data 
rx_mbps, tx_mbps = get_bandwidth_mbps()
en0_io            = psutil.net_io_counters(pernic=True).get(MAIN_IFACE)
now_label         = datetime.now().strftime("%H:%M:%S")
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
with ThreadPoolExecutor() as ex:
    futures = {k: ex.submit(get_ping_ms, v) for k, v in PING_TARGETS.items()}
    ping_results = {}
    for k, fut in futures.items():
        try:
            ping_results[k] = fut.result(timeout=2.5)
        except Exception:
            ping_results[k] = None

ts_list, rx_list, tx_list = _read_history()
ts_list.append(now_label)
rx_list.append(round(rx_mbps, 4))
tx_list.append(round(tx_mbps, 4))
_write_history(ts_list, rx_list, tx_list)

for k, v in ping_results.items():
    st.session_state.ping_history[k].append(v if v is not None else 0)

ts  = ts_list[-HISTORY_LEN:]
rxh = rx_list[-HISTORY_LEN:]
txh = tx_list[-HISTORY_LEN:]

st.markdown("##  Network Monitor")
st.caption(f"Last updated: **{now_label}**  •  Auto-refresh every {REFRESH_MS//1000}s")

c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("⬇ Download",  f"{rx_mbps:.2f} MB/s")
c2.metric("⬆ Upload",    f"{tx_mbps:.2f} MB/s")
c3.metric("Total Recv",  fmt_bytes(en0_io.bytes_recv) if en0_io else "—")
c4.metric("Total Sent",  fmt_bytes(en0_io.bytes_sent) if en0_io else "—")
c5.metric("Interfaces",  str(len(psutil.net_if_stats())))

st.markdown("---")

col_bw, col_ping = st.columns(2)

with col_bw:
    st.markdown('<p class="section-title">Bandwidth — MB/s</p>', unsafe_allow_html=True)
    fig_bw = go.Figure()
    fig_bw.add_trace(go.Scatter(
        x=ts, y=rxh, name="RX ⬇",
        line=dict(color="#60a5fa", width=2),
        fill="tozeroy", fillcolor="rgba(96,165,250,0.12)"
    ))
    fig_bw.add_trace(go.Scatter(
        x=ts, y=txh, name="TX ⬆",
        line=dict(color="#34d399", width=2),
        fill="tozeroy", fillcolor="rgba(52,211,153,0.12)"
    ))
    fig_bw.update_layout(
        height=260, margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", y=1.1, x=0),
        xaxis=dict(showgrid=False, tickfont=dict(size=10), nticks=6),
        yaxis=dict(gridcolor="#2a2a3e", tickfont=dict(size=10)),
    )
    st.plotly_chart(fig_bw, use_container_width=True)

with col_ping:
    st.markdown('<p class="section-title">Latency — ms</p>', unsafe_allow_html=True)
    colors = ["#f472b6", "#a78bfa", "#fb923c"]
    fig_ping = go.Figure()
    for i, (label, _) in enumerate(PING_TARGETS.items()):
        ph = list(st.session_state.ping_history[label])
        fig_ping.add_trace(go.Scatter(
            x=ts, y=ph, name=label,
            line=dict(color=colors[i % len(colors)], width=2),
        ))
    fig_ping.update_layout(
        height=260, margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", y=1.1, x=0),
        xaxis=dict(showgrid=False, tickfont=dict(size=10), nticks=6),
        yaxis=dict(gridcolor="#2a2a3e", tickfont=dict(size=10)),
    )
    st.plotly_chart(fig_ping, use_container_width=True)

col_ps, col_if = st.columns(2)

with col_ps:
    st.markdown('<p class="section-title">Ping Status</p>', unsafe_allow_html=True)
    for label, ms in ping_results.items():
        st.markdown(f"**{label}** &nbsp; {ping_badge(ms)}", unsafe_allow_html=True)
        st.write("")

with col_if:
    st.markdown('<p class="section-title">Network Interfaces</p>', unsafe_allow_html=True)
    stats  = psutil.net_if_stats()
    addrs  = psutil.net_if_addrs()
    ifaces = [(name, s) for name, s in stats.items() if s.isup]
    for name, s in ifaces[:6]:
        ip = "—"
        for addr in addrs.get(name, []):
            if addr.family == socket.AF_INET:
                ip = addr.address
                break
        badge = '<span class="badge-ok">UP</span>'
        st.markdown(f"{badge} &nbsp; **{name}** &nbsp; `{ip}` &nbsp; {s.speed} Mbps", unsafe_allow_html=True)
        st.write("")

st.markdown("---")
st.markdown('<p class="section-title">Active Connections</p>', unsafe_allow_html=True)
conns = get_top_connections()
if conns:
    st.dataframe(conns, use_container_width=True, hide_index=True)
else:
    st.caption("No active connections found (may need elevated permissions).")

