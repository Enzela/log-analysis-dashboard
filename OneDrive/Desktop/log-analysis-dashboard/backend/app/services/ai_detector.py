def detect_threats(event_type: str):
    threat_map = {
        "brute_force": ("Critical", 0.95),
        "file_access": ("High", 0.85),
        "port_scan": ("High", 0.80),
        "login_failed": ("Medium", 0.60),
        "login_success": ("Low", 0.10),
    }
    return threat_map.get(event_type.lower(), ("Low", 0.10))