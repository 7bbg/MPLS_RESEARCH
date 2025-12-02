import json

input_path = "data/test.json"
output_path = "data/test_clean.json"

events = []
with open(input_path, "r") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            events.append(obj)
        except Exception:
            continue

# Save as a single object with an array of events
with open(output_path, "w") as f:
    json.dump({"events": events}, f, indent=2)
