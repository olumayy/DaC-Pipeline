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
        
        # Kibana Saved Objects hide the query inside a stringified JSON payload
        search_source_str = attributes.get("kibanaSavedObjectMeta", {}).get("searchSourceJSON", "{}")
        
        # Convert that string back into a Python dictionary
        search_source_json = json.loads(search_source_str)
        
        # Finally, extract the actual Lucene query
        query_string = search_source_json.get("query", {}).get("query", "")
        
        if not query_string:
            print("CRITICAL: Query string is empty. Aborting deployment to prevent alert storm!")
            return

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
    
    # Attempt to Create (POST)
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code == 200:
        print("✅ Successfully created new rule!")
    elif response.status_code == 409:
        print("⚠️ Rule already exists. Attempting to Update (PUT)...")
        
        # If it exists, Elastic requires a PUT request targeted at the specific rule_id
        update_url = f"{url}?rule_id={payload['rule_id']}"
        update_response = requests.put(update_url, headers=headers, json=payload)
        
        if update_response.status_code == 200:
            print("✅ Successfully updated the existing rule!")
        else:
            print(f"❌ Update Failed! Status: {update_response.status_code}, Response: {update_response.text}")
            exit(1) # Force GitHub Actions to show a red 'X' if it fails
    else:
        print(f"❌ Creation Failed! Status: {response.status_code}, Response: {response.text}")
        exit(1) # Force GitHub Actions to show a red 'X' if it fails

if __name__ == "__main__":
    deploy()
