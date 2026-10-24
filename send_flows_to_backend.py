
import time
import pandas as pd
import requests

INPUT_FILE = "extracted_flows.csv"
BACKEND_URL = "http://localhost:8080/api/traffic/ingest"
OUTPUT_FILE = "backend_ingestion_results.csv"

MAX_ATTEMPTS = 3
TIMEOUT = 30

flows = pd.read_csv(INPUT_FILE)
results = []

for index, flow in flows.iterrows():
    # Match the fields expected by TrafficIngestRequest.java
    payload = {
        "sourceIp": str(flow["source_ip"]),
        "duration": float(flow["duration_seconds"]),
        "protocolType": str(flow["protocol"]).lower(),
        "service": "other",
        "flag": "SF",
        "srcBytes": float(flow["total_bytes"]),
        "dstBytes": 0.0,
        "count": float(flow["packet_count"]),
        "srvCount": float(flow["packet_count"]),
        "serrorRate": 0.0,
        "sameSrvRate": 1.0,
        "diffSrvRate": 0.0,
        "dstHostCount": float(flow["packet_count"]),
        "dstHostSrvCount": float(flow["packet_count"]),
    }

    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = requests.post(
                BACKEND_URL,
                json=payload,
                timeout=TIMEOUT
            )
            response.raise_for_status()
            saved_record = response.json()

            results.append({
                "source_ip": payload["sourceIp"],
                "destination_ip": str(flow["destination_ip"]),
                "protocol": payload["protocolType"],
                "prediction": saved_record.get("prediction"),
                "is_malicious": saved_record.get("malicious"),
                "confidence": saved_record.get("confidence"),
                "status": "success",
                "error": ""
            })

            last_error = None
            break

        except requests.RequestException as exc:
            last_error = str(exc)
            if attempt < MAX_ATTEMPTS:
                print(
                    f"Retrying flow {index + 1} "
                    f"(attempt {attempt}/{MAX_ATTEMPTS})"
                )
                time.sleep(1)

    if last_error is not None:
        results.append({
            "source_ip": payload["sourceIp"],
            "destination_ip": str(flow["destination_ip"]),
            "protocol": payload["protocolType"],
            "prediction": None,
            "is_malicious": None,
            "confidence": None,
            "status": "failed",
            "error": last_error
        })

    # Save progress after every flow.
    pd.DataFrame(results).to_csv(OUTPUT_FILE, index=False)
    print(f"Processed {index + 1}/{len(flows)}")

results_df = pd.DataFrame(results)

print("\n========== BACKEND INGESTION SUMMARY ==========")
print(f"Total flows: {len(flows)}")
print(f"Successfully ingested: {(results_df['status'] == 'success').sum()}")
print(f"Failed: {(results_df['status'] == 'failed').sum()}")
print(f"Report saved to: {OUTPUT_FILE}")
print("================================================")
