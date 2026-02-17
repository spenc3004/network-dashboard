import logging
import platform
import socket
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh
from scapy.all import IP, TCP, UDP, conf, get_if_addr, get_if_list, sniff

try:
    from scapy.arch.windows import get_windows_if_list
except Exception:  # pragma: no cover - best-effort on non-Windows
    get_windows_if_list = None

logging.basicConfig(level=logging.INFO)

WIFI_TOKENS = ("wi-fi", "wifi", "wireless", "wlan", "802.11", "airport")
# RUN WITH PRIVILEGES:
# - Windows: Run as Administrator and ensure Npcap is installed.  [streamlit run main.py]
# - Mac: Run with sudo or grant permissions to capture packets.  [sudo -E venv/bin/streamlit run main.py]

class PacketProcessor:
    def __init__(self):
        self.protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        self.stats = defaultdict(
            lambda: {
                "packet_count": 0,
                "dst_ips": set(),
                "dst_names": set(),
                "dst_ports": set(),
                "protocols": set(),
                "bytes": 0,
                "first_seen": None,
                "last_seen": None,
                "tcp_flags": set(),
                "tcp_packets": 0,
                "src_name": "",
            }
        )
        self.lock = threading.Lock()
        self.ip_cache: Dict[str, str] = {}
        self.port_map: Dict[int, str] = {
            80: "HTTP",
            443: "HTTPS",
            53: "DNS",
            22: "SSH",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            3306: "MySQL",
            5432: "Postgres",
            8080: "HTTP-Alt",
        }

    def resolve_name(self, ip: str) -> str:
        if not ip:
            return ""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ip
        self.ip_cache[ip] = name
        return name

    def get_protocol_name(self, proto_num: int) -> str:
        return self.protocol_map.get(proto_num, f"OTHER({proto_num})")

    def get_application(
        self, protocol_name: str, src_port: Optional[int], dst_port: Optional[int]
    ) -> Optional[str]:
        if protocol_name not in ["TCP", "UDP"]:
            return None
        if src_port and src_port in self.port_map:
            return self.port_map[src_port]
        if dst_port and dst_port in self.port_map:
            return self.port_map[dst_port]
        return None

    def process_packet(self, packet) -> None:
        try:
            if not packet.haslayer(IP):
                return

            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_name = self.resolve_name(src_ip)
            dst_name = self.resolve_name(dst_ip)
            protocol_num = ip_layer.proto
            protocol_name = self.get_protocol_name(protocol_num)
            timestamp = datetime.fromtimestamp(packet.time)
            src_port = dst_port = None

            if protocol_name == "TCP" and packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)
            else:
                flags = None

            if protocol_name == "UDP" and packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            _ = self.get_application(protocol_name, src_port, dst_port)

            with self.lock:
                stat = self.stats[src_ip]
                if not stat["src_name"]:
                    stat["src_name"] = src_name
                stat.setdefault("dst_names", set())
                stat["packet_count"] += 1
                stat["dst_ips"].add(dst_ip)
                stat["dst_names"].add(dst_name)
                stat["bytes"] += len(packet)
                stat["protocols"].add(protocol_name)
                if dst_port:
                    stat["dst_ports"].add(dst_port)
                if protocol_name == "TCP" and flags:
                    stat["tcp_flags"].add(flags)
                    stat["tcp_packets"] += 1
                if stat["first_seen"] is None:
                    stat["first_seen"] = timestamp
                stat["last_seen"] = timestamp

        except Exception as exc:
            logging.error("Error processing packet: %s", exc)

    def get_stats(self):
        result = {}
        with self.lock:
            for ip, stat in self.stats.items():
                result[ip] = {
                    **stat,
                    "src_name": stat.get("src_name", ""),
                    "dst_ips": list(stat["dst_ips"]),
                    "dst_names": list(stat.get("dst_names", set())),
                    "dst_ports": list(stat["dst_ports"]),
                    "protocols": list(stat["protocols"]),
                    "tcp_flags": list(stat["tcp_flags"]),
                    
                }
        return result


def _is_non_loopback_ipv4(ip: Optional[str]) -> bool:
    if not ip:
        return False
    if ip.startswith("127."):
        return False
    if ip.startswith("169.254."):
        return False
    return True


def _windows_iface_ips(iface: dict) -> List[str]:
    for key in ("ips", "ipv4", "ip"):
        value = iface.get(key)
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return value
    return []


def _score_windows_iface(iface: dict) -> int:
    name = (iface.get("name") or "").lower()
    desc = (iface.get("description") or "").lower()
    text = f"{name} {desc}"

    score = 0
    if any(token in text for token in WIFI_TOKENS):
        score += 5
    if any(_is_non_loopback_ipv4(ip) for ip in _windows_iface_ips(iface)):
        score += 2
    if any(token in text for token in ("virtual", "loopback", "tunnel")):
        score -= 5
    return score


def _format_windows_npf(guid: str) -> str:
    if guid.startswith("{") and guid.endswith("}"):
        return f"\\Device\\NPF_{guid}"
    return f"\\Device\\NPF_{{{guid}}}"


def _find_wifi_interface_windows() -> Optional[str]:
    if get_windows_if_list is None:
        return None

    interfaces = get_windows_if_list()
    if not interfaces:
        return None

    best = max(interfaces, key=_score_windows_iface)
    pcap_name = best.get("pcap_name") or best.get("name")
    if isinstance(pcap_name, str) and pcap_name.lower().startswith("\\device\\npf_"):
        return pcap_name

    guid = best.get("guid")
    if isinstance(guid, str) and guid:
        return _format_windows_npf(guid)

    return pcap_name if isinstance(pcap_name, str) else None


def _find_wifi_interface_mac() -> Optional[str]:
    try:
        output = subprocess.check_output(
            ["/usr/sbin/networksetup", "-listallhardwareports"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        current_port = None
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Hardware Port:"):
                current_port = line.split(":", 1)[1].strip().lower()
            elif line.startswith("Device:") and current_port:
                device = line.split(":", 1)[1].strip()
                if current_port in ("wi-fi", "airport"):
                    return device
    except Exception:
        pass

    for iface in get_if_list():
        if not iface.startswith("en"):
            continue
        try:
            ip = get_if_addr(iface)
        except Exception:
            continue
        if _is_non_loopback_ipv4(ip):
            return iface

    try:
        if conf.iface:
            ip = get_if_addr(conf.iface)
            if _is_non_loopback_ipv4(ip):
                return conf.iface
    except Exception:
        pass

    return None


def find_wifi_interface() -> Optional[str]:
    system = platform.system()
    if system == "Windows":
        return _find_wifi_interface_windows()
    if system == "Darwin":
        return _find_wifi_interface_mac()

    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            continue
        if _is_non_loopback_ipv4(ip):
            return iface
    return None


def stats_to_dataframe(processor: PacketProcessor) -> pd.DataFrame:
    stats = processor.get_stats()
    rows = []
    for src_ip, data in stats.items():
        source_name = data.get("src_name", "")
        if not source_name or source_name == src_ip:
            source_name = "Source name couldn't be resolved"

        unresolved_dest_msg = "Destination name couldn't be resolved"
        dest_name_candidates = data.get("dst_names", [])
        dest_ips = set(data.get("dst_ips", []))
        display_dest_names = sorted(
            {
                unresolved_dest_msg if (not name or name in dest_ips) else name
                for name in dest_name_candidates
            }
        )

        rows.append(
            {
                "Source IP": src_ip,
                "Source Name": source_name,
                "Packets": data["packet_count"],
                "Bytes": data["bytes"],
                "TCP Packets": data["tcp_packets"],
                "Dest IPs": ", ".join(data["dst_ips"]),
                "Dest Names": ", ".join(display_dest_names),
                "Dest Ports": ", ".join(map(str, data["dst_ports"])),
                "Protocols": ", ".join(data["protocols"]),
                "TCP Flags": ", ".join(data["tcp_flags"]),
                "First Seen": data["first_seen"],
                "Last Seen": data["last_seen"],
            }
        )
    df = pd.DataFrame(rows)
    if not df.empty:
        df.sort_values("Packets", ascending=False, inplace=True)
    return df


def real_time_packets(
    processor: PacketProcessor,
    stop_event: threading.Event,
    interface: Optional[str] = None,
) -> Optional[threading.Thread]:
    def capture_loop():
        try:
            while not stop_event.is_set():
                sniff(
                    prn=processor.process_packet,
                    iface=interface,
                    store=False,
                    timeout=1,
                )
        except Exception as exc:
            logging.error("Packet capture thread error: %s", exc)

    try:
        thread = threading.Thread(target=capture_loop, daemon=True)
        thread.start()
        logging.info("Packet capture thread started")
        return thread
    except Exception as exc:
        logging.error("Failed to start packet capture thread: %s", exc)
        return None


def ensure_state_initialized() -> None:
    if "processor" not in st.session_state:
        st.session_state.processor = PacketProcessor()
    if "stop_event" not in st.session_state:
        st.session_state.stop_event = threading.Event()
    if "capture_enabled" not in st.session_state:
        st.session_state.capture_enabled = True


def ensure_capture_running() -> None:
    ensure_state_initialized()

    if not st.session_state.capture_enabled:
        return

    thread = st.session_state.get("capture_thread")
    if thread is not None and thread.is_alive():
        return

    st.session_state.stop_event.clear()
    interface = find_wifi_interface()
    st.session_state.capture_interface = interface
    st.session_state.capture_thread = real_time_packets(
        st.session_state.processor,
        stop_event=st.session_state.stop_event,
        interface=interface,
    )
    st.session_state.start_time = time.time()


st.title("Real-Time Network Traffic Analyzer")

ensure_capture_running()

st.header("Live Network Traffic Stats")
st.write("Capturing packets in real-time and displaying aggregated stats per source IP.")

interface_label = st.session_state.get("capture_interface")
if interface_label:
    st.caption(f"Capturing on interface: {interface_label}")
else:
    st.warning("Wi-Fi interface not detected. Using default interface if available.")

thread = st.session_state.get("capture_thread")
if thread is None or not thread.is_alive():
    st.warning("Packet capture thread is not running.")
    st.info("On Windows, run as Administrator and ensure Npcap is installed.")

stats_df = stats_to_dataframe(st.session_state.processor)

total_packets = int(stats_df["Packets"].sum()) if not stats_df.empty else 0

packets_col, duration_col = st.columns(2)
with packets_col:
    st.metric("Total Packets", total_packets)
with duration_col:
    if "start_time" in st.session_state:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Time", f"{duration:.2f} seconds")

st.subheader("Recent Stats")
if not stats_df.empty:
    st.dataframe(stats_df , width="stretch")
    st.success("Stats updated successfully.")
else:
    st.info("No packets captured yet. Please wait...")

start, stop = st.columns(2)
with start:
    if st.button("Start Capture"):
        st.session_state.capture_enabled = True
        ensure_capture_running()
        st.rerun()
with stop:
    if st.button("Stop Capture"):
        st.session_state.capture_enabled = False
        st.session_state.stop_event.set()
        thread = st.session_state.get("capture_thread")
        if thread is not None:
            thread.join(timeout=2)
        st.info("Capture stopped.")

st.caption("Auto-refreshes every 2 seconds while running.")
if st.session_state.get("capture_enabled", True):
    count = st_autorefresh(interval=2000, limit=100, key="autorefresh")
