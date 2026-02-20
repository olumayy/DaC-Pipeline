import os
import yaml
import requests
import subprocess

ELASTIC_URL = os.getenv('ELASTIC_URL')
API_KEY = os.getenv('ELASTIC_API_KEY')

def deploy():
    # In a fully scaled environment, we would loop through every file in the rules/ folder.
    # For now, we point it directly at your file.
    rule_file = 'rules/suspicious_powershell.yml'
    
    # 1. Read the raw Sigma YAML for metadata
    try:
        with open(rule_file, 'r') as f:
            sigma_rule = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Failed to read YAML file: {e}")
        return
        
    title = sigma_rule.get('title', 'Unnamed Rule')
    description = sigma_rule.get('description', 'Deployed via DaC Pipeline')
    rule_id = sigma_rule.get('id', 'custom-dac-rule')
    
    # 2. Ask Sigma CLI to translate ONLY the query string (bypassing JSON wrappers)
    print(f"Translating logic for: {title}...")
    command = f"sigma convert -t lucene -p ecs_windows {rule_file}"
    
    # Execute the CLI command directly from Python
    process = subprocess.run(command, shell=True, capture_output=True, text=True)
    query_string = process.stdout.strip()
    
    if not query_string or "Error" in query_string:
        print(f"❌ Failed to extract raw query! CLI Output: {query_string}")
        exit(1)
        
    print(f"✅ Successfully extracted query: {query_string}")

    # 3. Build the pristine Elastic API Payload
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

    # 4. The Upsert Logic
    url = f"{ELASTIC_URL}/api/detection_engine/rules"
    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
        "Authorization": f"ApiKey {API_KEY}"
    }

    print(f"Deploying Enterprise Rule: {payload['name']}...")
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print("✅ Successfully created new rule!")
    elif response.status_code == 409:
        print("⚠️ Rule already exists. Attempting to Update (PUT)...")
        update_url = f"{url}?rule_id={payload['rule_id']}"
        update_response = requests.put(update_url, headers=headers, json=payload)
        
        if update_response.status_code == 200:
            print("✅ Successfully updated the existing rule with the proper query!")
        else:
            print(f"❌ Update Failed! Status: {update_response.status_code}, Response: {update_response.text}")
            exit(1)
    else:
        print(f"❌ Creation Failed! Status: {response.status_code}, Response: {response.text}")
        exit(1)

if __name__ == "__main__":
    deploy()
