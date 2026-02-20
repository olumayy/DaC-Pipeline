import os
import json
import requests

ELASTIC_URL = os.getenv('ELASTIC_URL')
API_KEY = os.getenv('ELASTIC_API_KEY')

def deploy():
    if not os.path.exists('kibana_alerts.ndjson'):
        print("Error: Translated NDJSON file not found!")
        return

    # 1. Read the NDJSON file (Newline Delimited JSON)
    with open('kibana_alerts.ndjson', 'r') as f:
        lines = f.readlines()

    # 2. Parse the first rule
    try:
        rule_object = json.loads(lines[0])
        attributes = rule_object.get("attributes", {})
        
        # Extract the raw Lucene query string
        query_data = attributes.get("query", "")
        if isinstance(query_data, dict):
            query_string = query_data.get("query", "")
        else:
            query_string = query_data

        rule_id = rule_object.get("id", "custom-dac-rule")
        title = attributes.get("title", "Unnamed Sigma Rule")
        description = attributes.get("description", "Deployed via DaC Pipeline")
        
    except Exception as e:
        print(f"Error parsing NDJSON: {e}")
        return

    # 3. Build the strict Detection Engine Payload
    payload = {
        "name": f"DaC - {title}",
        "type": "query",
        "description": description,
        "enabled": True,
        "query": query_string,
        "severity": "high",
        "risk_score": 73,
        "interval": "5m",
        "from": "now-6m",
        "rule_id": rule_id,
        "index": ["logs-*"],
        "tags": ["Detection-as-Code"]
    }

    # 4. Ship it to the Production API
    url = f"{ELASTIC_URL}/api/detection_engine/rules"
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {API_KEY}"
    }

    print(f"Deploying Enterprise Rule: {payload['name']}...")
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print("✅ Successfully deployed to Detection Engine!")
    elif response.status_code == 409:
        print("⚠️ Rule already exists. (To update rules, we would use a PUT request here).")
    else:
        print(f"❌ Failed! Status: {response.status_code}, Response: {response.text}")

if __name__ == "__main__":
    deploy()
