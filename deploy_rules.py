import os
import yaml
import requests
import subprocess
import glob # <-- NEW: This library allows us to search for files

ELASTIC_URL = os.getenv('ELASTIC_URL')
API_KEY = os.getenv('ELASTIC_API_KEY')

def deploy():
    # NEW: Find every .yml file inside the rules folder
    rule_files = glob.glob('rules/*.yml')
    
    if not rule_files:
        print("⚠️ No YAML rules found in the 'rules/' directory.")
        return
        
    print(f"🚀 Found {len(rule_files)} rules. Starting mass deployment...")

    # NEW: Loop through each file one by one
    for rule_file in rule_files:
        print("-" * 50)
        print(f"Processing: {rule_file}")
        
        # 1. Read the raw Sigma YAML for metadata
        try:
            with open(rule_file, 'r') as f:
                sigma_rule = yaml.safe_load(f)
        except Exception as e:
            print(f"❌ Failed to read {rule_file}: {e}. Skipping to next rule...")
            continue # <-- NEW: 'continue' skips to the next file instead of crashing the script
            
        title = sigma_rule.get('title', 'Unnamed Rule')
        description = sigma_rule.get('description', 'Deployed via DaC Pipeline')
        rule_id = sigma_rule.get('id', 'custom-dac-rule')
        
        # 2. Ask Sigma CLI to translate ONLY the query string
        command = f"sigma convert -t lucene -p ecs_windows {rule_file}"
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        query_string = process.stdout.strip()
        
        if not query_string or "Error" in query_string:
            print(f"❌ Failed to extract raw query for {title}! CLI Output: {query_string}")
            continue # Skip to next rule
            
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

        # Attempt to Create (POST)
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 200:
            print(f"✅ Created: {title}")
        elif response.status_code == 409:
            # If it exists, Update (PUT)
            update_url = f"{url}?rule_id={payload['rule_id']}"
            update_response = requests.put(update_url, headers=headers, json=payload)
            
            if update_response.status_code == 200:
                print(f"🔄 Updated: {title}")
            else:
                print(f"❌ Update Failed for {title}: {update_response.text}")
        else:
            print(f"❌ Creation Failed for {title}: {response.text}")

    print("-" * 50)
    print("🎉 Mass deployment complete!")

if __name__ == "__main__":
    deploy()
