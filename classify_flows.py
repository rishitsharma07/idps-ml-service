
import time
import pandas as pd
import requests

INPUT_FILE = "extracted_flows.csv"
OUTPUT_FILE = "classified_flows.csv"
API_URL = "http://127.0.0.1:8000/classify"

MAX_ATTEMPTS = 3
REQUEST_TIMEOUT = 30

def classify_flow(record):
    """Send a flow to the ML API, retrying temporary timeouts."""
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = requests.post(
                API_URL,
                json=record,
                timeout=REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.json()

        except requests.Timeout:
            print(
                f"Timeout for {record['source_ip']} "
                f"(attempt {attempt}/{MAX_ATTEMPTS})"
            )

            if attempt < MAX_ATTEMPTS:
                time.sleep(1)

        except requests.RequestException:
            # Retry temporary connection or server errors.
            if attempt < MAX_ATTEMPTS:
                print(
                    f"Request error for {record['source_ip']} "
                    f"(attempt {attempt}/{MAX_ATTEMPTS})"
                )
                time.sleep(1)
            else:
                raise

    raise TimeoutError(
        f"Prediction timed out after {MAX_ATTEMPTS} attempts"
    )


def main():
    flows = pd.read_csv(INPUT_FILE)
    results = []

    total = len(flows)

    for index, flow in flows.iterrows():
        record = {
            "source_ip": str(flow["source_ip"]),
            "duration": float(flow["duration_seconds"]),
            "protocol_type": str(flow["protocol"]),
            "service": "other",
            "flag": "SF",
            "src_bytes": float(flow["total_bytes"]),
            "dst_bytes": 0.0,
            "count": float(flow["packet_count"]),
            "srv_count": float(flow["packet_count"]),
            "serror_rate": 0.0,
            "same_srv_rate": 1.0,
            "diff_srv_rate": 0.0,
            "dst_host_count": float(flow["packet_count"]),
            "dst_host_srv_count": float(flow["packet_count"]),
        }

        base_result = {
            "source_ip": record["source_ip"],
            "destination_ip": str(flow["destination_ip"]),
            "protocol": str(flow["protocol"]),
            "packet_count": int(flow["packet_count"]),
            "total_bytes": int(flow["total_bytes"]),
            "duration_seconds": float(flow["duration_seconds"]),
        }

        try:
            prediction = classify_flow(record)

            result = {
                **base_result,
                "prediction": prediction["prediction"],
                "is_malicious": prediction["is_malicious"],
                "confidence": prediction["confidence"],
                "status": "success",
                "error": "",
            }

        except (
            requests.RequestException,
            TimeoutError,
            ValueError,
            KeyError,
        ) as exc:
            result = {
                **base_result,
                "prediction": "error",
                "is_malicious": False,
                "confidence": None,
                "status": "failed",
                "error": str(exc),
            }

            print(
                f"Failed flow {index + 1}: "
                f"{base_result['source_ip']} -> "
                f"{base_result['destination_ip']}: {exc}"
            )

        results.append(result)

        # Save after each flow so completed results aren't lost
        # if the script is interrupted.
        pd.DataFrame(results).to_csv(OUTPUT_FILE, index=False)

        print(f"Processed {index + 1}/{total}")

    results_df = pd.DataFrame(results)
    successful = results_df[results_df["status"] == "success"]
    failed = results_df[results_df["status"] == "failed"]
    malicious = successful[successful["is_malicious"] == True]

    print("\n========== CLASSIFICATION SUMMARY ==========")
    print(f"Total flows: {total}")
    print(f"Successful predictions: {len(successful)}")
    print(f"Failed predictions: {len(failed)}")
    print(f"Flagged as potentially malicious: {len(malicious)}")
    print(f"Report saved to: {OUTPUT_FILE}")
    print("============================================")


if __name__ == "__main__":
    main()
