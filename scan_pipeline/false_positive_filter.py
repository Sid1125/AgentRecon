def is_false_positive(port_info):
    known_safe_ports = ["80", "443", "22"]
    if port_info["port"] in known_safe_ports and port_info["product"] != "":
        return True
    if "filtered" in port_info.get("state", ""):
        return True
    return False

def filter_ports(port_list):
    return [p for p in port_list if not is_false_positive(p)]

if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python false_positive_filter.py <enriched_result.json>")
    else:
        with open(sys.argv[1]) as f:
            data = json.load(f)
        filtered = filter_ports(data.get("ports", []))
        data["ports"] = filtered
        print(json.dumps(data, indent=2))
