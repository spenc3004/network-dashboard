import streamlit as st
import pandas as pd
#import plotly.express as px
#import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.http import HTTPRequest
from collections import defaultdict
import time
from datetime import datetime
import warnings
from typing import Dict, List, Optional
import threading
import socket
import logging
from typing import Dict, Optional
from scapy.arch.windows import get_windows_if_list



class PacketProcessor:
    def __init__(self):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
        }
        # Thread-safe dictionary to store stats per source IP
        self.stats = defaultdict(lambda: {
            "packet_count": 0,
            "dst_ips": set(),
            "dst_ports": set(),
            "protocols": set(),
            "bytes": 0,
            "first_seen": None,
            "last_seen": None,
            "tcp_flags": set(),
            "tcp_packets": 0
        })
        self.lock = threading.Lock()
        self.ip_cache: Dict[str, str] = {}
        self.port_map: Dict[int, str] = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH',
            25: 'SMTP', 110: 'POP3', 143: 'IMAP', 3306: 'MySQL',
            5432: 'Postgres', 8080: 'HTTP-Alt',
        }

    def resolve_name(self, ip: str) -> str:
        if not ip:
            return ''
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            name = ip
        self.ip_cache[ip] = name
        return name

    def get_protocol_name(self, proto_num: int) -> str:
        return self.protocol_map.get(proto_num, f'OTHER({proto_num})')

    def get_application(self, protocol_name: str, src_port: Optional[int], dst_port: Optional[int]) -> Optional[str]:
        if protocol_name not in ['TCP', 'UDP']:
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
            protocol_num = ip_layer.proto
            protocol_name = self.get_protocol_name(protocol_num)
            timestamp = datetime.fromtimestamp(packet.time)
            src_port = dst_port = None
            application = None

            if protocol_name == 'TCP' and packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = str(tcp_layer.flags)
            else:
                flags = None

            if protocol_name == 'UDP' and packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            application = self.get_application(protocol_name, src_port, dst_port)

            with self.lock:
                stat = self.stats[src_ip]
                stat["packet_count"] += 1
                stat["dst_ips"].add(dst_ip)
                stat["bytes"] += len(packet)
                stat["protocols"].add(protocol_name)
                if dst_port:
                    stat["dst_ports"].add(dst_port)
                if protocol_name == 'TCP' and flags:
                    stat["tcp_flags"].add(flags)
                    stat["tcp_packets"] += 1
                if stat["first_seen"] is None:
                    stat["first_seen"] = timestamp
                stat["last_seen"] = timestamp

        except Exception as e:
            logging.error(f"Error processing packet: {e}")

    def get_stats(self):
        # Convert sets to lists for easier serialization
        result = {}
        with self.lock:
            for ip, stat in self.stats.items():
                result[ip] = {
                    **stat,
                    "dst_ips": list(stat["dst_ips"]),
                    "dst_ports": list(stat["dst_ports"]),
                    "protocols": list(stat["protocols"]),
                    "tcp_flags": list(stat["tcp_flags"]),
                }
        return result
    
def display_stats(processor: PacketProcessor):
    stats = processor.get_stats()
    if not stats:
        print("No packets captured yet.")
        return

    # Convert stats dict to DataFrame
    rows = []
    for src_ip, data in stats.items():
        rows.append({
            "Source IP": src_ip,
            "Packets": data["packet_count"],
            "Bytes": data["bytes"],
            "TCP Packets": data["tcp_packets"],
            "Dest IPs": ", ".join(data["dst_ips"]),
            "Dest Ports": ", ".join(map(str, data["dst_ports"])),
            "Protocols": ", ".join(data["protocols"]),
            "TCP Flags": ", ".join(data["tcp_flags"]),
            "First Seen": data["first_seen"],
            "Last Seen": data["last_seen"]
        })
    df = pd.DataFrame(rows)
    #print(df.to_string(index=False))
    #print("-" * 80)


def real_time_packets(processor: PacketProcessor, interface: Optional[str] = None):
    def capture_packets():
        try:
            sniff(prn=processor.process_packet, iface=interface, store=False)
        except Exception as e:
            logging.error(f"Packet capture thread error: {e}")
    try:
        thread = threading.Thread(target=capture_packets, daemon=True, args=(stop_event))
        thread.start()
        logging.info("Packet capture thread started")
        return thread
    except Exception as e:
        logging.error(f"Failed to start packet capture thread: {e}")
        return None


def stop_capture(stop_event):
    while not stop_event.is_set():
        pass
    st.info("Stopping packet capture...")

stop_event = threading.Event()

def main():
    # Initialize processor and thread
    if 'processor' not in st.session_state:
        st.session_state.processor = PacketProcessor()
        capture_thread = real_time_packets(st.session_state.processor, interface="\\Device\\NPF_{8D796711-983F-45B8-9A75-BD014D11E8D8}")
        st.session_state.capture_thread = capture_thread
        st.session_state.start_time = time.time()

        if st.session_state.capture_thread is None or not st.session_state.capture_thread.is_alive():
            st.warning("[WARNING] Packet capture may not be running.")
            st.info("On Windows, ensure the script is run as administrator and NPCAP is installed.")
        else:
            st.success("[INFO] Packet capture started (running in background thread).")


    try:
        # Periodically display stats
        while True:
            '''
            interfaces = get_windows_if_list()
            for iface in interfaces:
                print(f"Name: {iface['name']}")
                print(f"Description: {iface['description']}")
                print(f"NPF Device: \\\\Device\\\\NPF_{iface['guid']}")
                print("-" * 60)
            '''
            display_stats(st.session_state.processor)
            time.sleep(2)  # adjust refresh rate as needed
    except KeyboardInterrupt:
        st.info("\n[INFO] Stopping packet capture...")
        st.info(f"[INFO] Runtime: {time.time() - st.session_state.start_time:.2f} seconds")

st.title("Real-Time Network Traffic Analyzer")
app = st.container()

with app:
    st.header("Live Network Traffic Stats")
    st.write("Capturing packets in real-time and displaying aggregated stats per source IP.")
    
    packets, time = st.columns(2)
    
    df = st.session_state.processor.display_stats()
    
    with packets:
        st.metric("Total Packets", len(df))
        
    with time:
        if 'start_time' in st.session_state:
            duration = time.time() - st.session_state.start_time
            st.metric("Capture Time", f"{duration:.2f} seconds")
            
    st.subheader("Recent Stats")
    
    if not df.empty:
        st.dataframe(df)
    else:
        st.write("No packets captured yet. Please wait...")

if st.button("Stop Capture"):
    st.info("Stopping packet capture...")
    stop_event.set()
    st.session_state.capture_thread.join()
    st.info(f"Capture stopped. Total runtime: {time.time() - st.session_state.start_time:.2f} seconds")
        

if __name__ == "__main__":
    main()