import pytest
from fastapi.testclient import TestClient
import json
import io
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.main import app

client = TestClient(app)

def test_upload_endpoint_exists():
    response = client.get("/")
    assert response.status_code == 200

def test_upload_json_log():
    log_data = [
        {"timestamp": "2026-06-20 10:15:23", "ip": "192.168.1.10", "event": "login_success", "message": "User logged in"},
        {"timestamp": "2026-06-20 11:20:45", "ip": "192.168.1.25", "event": "login_failed", "message": "Invalid password attempt"},
        {"timestamp": "2026-06-20 12:05:11", "ip": "10.0.0.5", "event": "port_scan", "message": "Multiple ports scanned"},
        {"timestamp": "2026-06-20 13:30:02", "ip": "203.0.113.7", "event": "file_access", "message": "Unauthorized file access"},
        {"timestamp": "2026-06-20 14:45:33", "ip": "192.168.1.50", "event": "brute_force", "message": "Multiple failed login attempts"}
    ]
    file_content = json.dumps(log_data).encode("utf-8")
    response = client.post(
        "/api/logs/upload",
        files={"file": ("sample_logs.json", io.BytesIO(file_content), "application/json")}
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Scan complete"

def test_ai_detection_severity():
    from app.services.ai_detector import detect_threats
    assert detect_threats("login_success") == ("Low", 0.10)
    assert detect_threats("login_failed") == ("Medium", 0.60)
    assert detect_threats("port_scan") == ("High", 0.80)
    assert detect_threats("file_access") == ("High", 0.85)
    assert detect_threats("brute_force") == ("Critical", 0.95)

def test_five_dummy_logs_detected():
    log_data = [
        {"timestamp": "2026-06-20 10:15:23", "ip": "192.168.1.10", "event": "login_success", "message": "User logged in"},
        {"timestamp": "2026-06-20 11:20:45", "ip": "192.168.1.25", "event": "login_failed", "message": "Invalid password attempt"},
        {"timestamp": "2026-06-20 12:05:11", "ip": "10.0.0.5", "event": "port_scan", "message": "Multiple ports scanned"},
        {"timestamp": "2026-06-20 13:30:02", "ip": "203.0.113.7", "event": "file_access", "message": "Unauthorized file access"},
        {"timestamp": "2026-06-20 14:45:33", "ip": "192.168.1.50", "event": "brute_force", "message": "Multiple failed login attempts"}
    ]
    file_content = json.dumps(log_data).encode("utf-8")
    response = client.post(
        "/api/logs/upload",
        files={"file": ("dummy_logs.json", io.BytesIO(file_content), "application/json")}
    )
    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 5
