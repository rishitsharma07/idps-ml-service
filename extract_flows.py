import pandas as pd

df = pd.read_csv("extracted_packets.csv")

# Identify a bidirectional flow using IPs, ports, and protocol
def flow_key(row):
    endpoints = sorted([
        (row["source_ip"], int(row["source_port"])),
        (row["destination_ip"], int(row["destination_port"]))
    ])
    return (endpoints[0], endpoints[1], row["protocol"])

df["flow"] = df.apply(flow_key, axis=1)

flows = []

for flow_id, group in df.groupby("flow"):
    first = group.iloc[0]

    flows.append({
        "source_ip": first["source_ip"],
        "destination_ip": first["destination_ip"],
        "protocol": first["protocol"],
        "packet_count": len(group),
        "total_bytes": int(group["packet_length"].sum()),
        "duration_seconds": round(
            group["time"].max() - group["time"].min(), 6
        ),
        "average_packet_length": round(
            group["packet_length"].mean(), 2
        ),
    })

result = pd.DataFrame(flows)
result.to_csv("extracted_flows.csv", index=False)

print("Flows extracted:", len(result))
print(result.head(10).to_string(index=False))
print("\nSaved to extracted_flows.csv")