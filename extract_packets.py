from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd

pcap_path = r"C:\Users\rishi\Downloads\idps_traffic.pcapng"

packets = rdpcap(pcap_path)
rows = []

for packet in packets:
    if IP not in packet:
        continue

    src_port = dst_port = 0
    protocol = "other"

    if TCP in packet:
        protocol = "tcp"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = "udp"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    rows.append({
        "time": float(packet.time),
        "source_ip": packet[IP].src,
        "destination_ip": packet[IP].dst,
        "protocol": protocol,
        "source_port": src_port,
        "destination_port": dst_port,
        "packet_length": len(packet),
    })

df = pd.DataFrame(rows)
df.to_csv("extracted_packets.csv", index=False)

print("Packets extracted:", len(df))
print(df.head())
print("Saved to extracted_packets.csv")