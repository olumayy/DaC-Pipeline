import os
import json
import requests

ELASTIC_URL = os.getenv('ELASTIC_URL')
API_KEY = os.getenv('ELASTIC_API_KEY')

def build_rule_payload(sigma_json_list):
    # pySigma-elasticsearch outputs a list of dicts. We'll process the first one.
    rule_data = sigma_json_list[0]
    
    # Staff Engineer Note: We're mapping Sigma fields to the specific 
    # requirements of the Elastic Detection Engine API.
    return {
        "name": f"DaC - {rule_data.get('title', 'Suspicious Activity')}",
        "type": "query",
        "description": rule_data.get("description", "Rule deployed via DaC Pipeline"),
        "enabled": True,
        "query": rule_data.get("query"), # This is the translated Lucene/ES query
        "severity": "high",
        "risk_score": 73,
        "interval": "5m",
        "from": "now-6m",
        "rule_id": rule_data.get("id"),
        "index": ["logs-*"],
        "tags": ["Detection-as-Code", "Staff-Engineer-Project"]
    }

def deploy():
    if not os.path.exists('kibana_alerts.json'):
        print("Error: Translated JSON file not found!")
        return

    with open('kibana_alerts.json', 'r') as f:
        translated_data = json.load(f)
    
    payload = build_rule_payload(translated_data)
    
    # The API endpoint for native SIEM rules
    url = f"{ELASTIC_URL}/api/detection_engine/rules"
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {API_KEY}"
    }

    print(f"Deploying Enterprise Rule: {payload['name']}...")
    # Using POST to create. (Note: If rule exists, use PUT to update)
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print("✅ Successfully deployed to Detection Engine!")
    elif response.status_code == 409:
        print("⚠️ Rule already exists. Staff Tip: Implement a PUT request here for updates!")
    else:
        print(f"❌ Failed! Status: {response.status_code}, Response: {response.text}")

if __name__ == "__main__":
    deploy()
