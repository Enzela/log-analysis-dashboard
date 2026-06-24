from fastapi import APIRouter, UploadFile, File, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.log_model import LogFile, LogEntry, Alert
from app.services.ai_detector import detect_threats
import json
from datetime import datetime

router = APIRouter()

@router.post("/api/logs/upload")
async def upload_log(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    content_str = content.decode("utf-8")

    # Save log file record
    log_file = LogFile(file_name=file.filename, user_id=1)
    db.add(log_file)
    db.commit()
    db.refresh(log_file)

    entries = []

    if file.filename.endswith(".json"):
        logs = json.loads(content_str)
        for log in logs:
            entries.append({
                "timestamp": log.get("timestamp"),
                "source_ip": log.get("ip"),
                "event_type": log.get("event"),
                "raw_log": log.get("message")
            })
    else:
        for line in content_str.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 5)
            if len(parts) >= 5:
                try:
                    entries.append({
                        "timestamp": f"{parts[0]} {parts[1]}",
                        "source_ip": parts[3],
                        "event_type": parts[4],
                        "raw_log": parts[5] if len(parts) > 5 else ""
                    })
                except Exception:
                    continue

    results = []
    for entry in entries:
        try:
            log_entry = LogEntry(
                log_file_id=log_file.id,
                timestamp=datetime.strptime(entry["timestamp"].strip(), "%Y-%m-%d %H:%M:%S"),
                source_ip=entry["source_ip"],
                event_type=entry["event_type"],
                raw_log=entry["raw_log"]
            )
            db.add(log_entry)
            db.commit()
            db.refresh(log_entry)

            severity, score = detect_threats(entry["event_type"])

            alert = Alert(
                log_entry_id=log_entry.id,
                threat_type=entry["event_type"],
                severity=severity,
                confidence_score=score,
                status="open"
            )
            db.add(alert)
            db.commit()

            results.append({
                "event": entry["event_type"],
                "source_ip": entry["source_ip"],
                "severity": severity,
                "confidence_score": score
            })
        except Exception as e:
            continue

    return {"message": "Scan complete", "results": results}