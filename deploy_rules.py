import os
import json
import requests

# Load environment variables from GitHub Secrets
ELASTIC_URL = os.getenv('ELASTIC_URL')
API_KEY = os.getenv('ELASTIC_API_KEY')

# Define the Rule Metadata the API requires
def build_rule_payload(sigma_json):
    # Sigma output is a list; we take the first item
    rule_data = sigma_json[0]
    
    return {
        "name": rule_data.get("title", "Unnamed Sigma Rule"),
        "type": "query",
        "description": rule_data.get("description", "No description provided"),
        "enabled": True,
        "query": rule_data.get("query"),
        "severity": "high",
        "risk_score": 73,
        "interval": "5m", # Run every 5 minutes
        "from": "now-6m", # Look back 6 minutes to ensure no gaps
        "rule_id": rule_data.get("id"),
        "index": ["logs-*"] # Target your live data view
    }

def deploy():
    # Load the translated rule from the pipeline
    with open('kibana_alerts.json', 'r') as f:
        translated_data = json.load(f)
    
    payload = build_rule_payload(translated_data)
    
    # Target the Detection Engine API endpoint
    url = f"{ELASTIC_URL}/api/detection_engine/rules"
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {API_KEY}"
    }

    print(f"Deploying rule: {payload['name']}...")
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print("Successfully deployed to Detection Engine!")
    else:
        print(f"Failed! Status: {response.status_code}, Response: {response.text}")

if __name__ == "__main__":
    deploy()
