import time
import requests

RAG_API_URL = "http://127.0.0.1:8000/api"
RAPP5_API_URL = "http://127.0.0.1:8001/api/v1/threats/share"

def orchestrate_threat_response(alert_description: str, indicators: list, component: str):
    print("-" * 60)
    print(f"CYBER PROBE ALERT: {alert_description}")
    print("-" * 60)
    
    # 1. Send to RAG API for Analysis
    print(" 1. Requesting AI Analysis from Teammate's RAG System...")
    rag_payload = {
        "attack_description": alert_description,
        "detected_indicators": indicators,
        "target_component": component
    }
    
    try:
        response = requests.post(f"{RAG_API_URL}/analyze", json=rag_payload, timeout=45)
        response.raise_for_status()
        analysis_data = response.json()["result"]
    except Exception as e:
        print(f" Failed to reach RAG API: {e}")
        return

    severity = analysis_data.get("severity_assessment", "UNKNOWN").upper()
    print(f" 2. AI Assessed Severity: {severity}")
    
    # 2. Dynamic Agentic Decision
    if severity in ["HIGH", "CRITICAL"]:
        print(" 3. CRITICAL THREAT DETECTED. Triggering Inter-Platform sharing via rApp 5...")
        
        # Format STIX
        stix_payload = {
            "type": "indicator",
            "id": f"indicator--{int(time.time())}",
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "name": f"Automated Detection: {component} Breach",
            "description": analysis_data.get("ai_analysis", "")[:200] + "...",
            "indicator_types": ["malicious-activity"],
            "pattern": f"[network-traffic:dst_ref.value = '{indicators[0]}']",
            "pattern_type": "stix",
            "valid_from": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }
        
        try:
            r5_response = requests.post(RAPP5_API_URL, json=stix_payload, timeout=5)
            if r5_response.status_code == 200:
                print(" 4. Successfully handed off to rApp 5 for peer distribution.")
            else:
                print(f" rApp 5 rejected payload: {r5_response.status_code}")
        except Exception as e:
            print(f" Failed to reach rApp 5: {e}")
    else:
        print(" 3. Threat is low/medium severity. Handled locally. No peer sharing required.")

if __name__ == "__main__":
    # Test 1: High Severity
    orchestrate_threat_response(
        alert_description="Successful unauthorized root access to O-Cloud management plane and ransomware encryption started.",
        indicators=["192.168.1.100", "ransomware.exe"],
        component="O-Cloud"
    )