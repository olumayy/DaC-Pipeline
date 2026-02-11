TARGET_EVENT = 4624

logs = [
    {"event_id": 4624, "user": "admin"},
    {"event_id": 4688, "user": "bob"},
    {"event_id": 4624, "user": "alice"}
]

matches = []

for log in logs:
    if log["event_id"] == TARGET_EVENT:
        matches.append(log)

print(matches)
