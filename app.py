# app.py - receives Splunk alerts, runs AI triage, shows a review page
# Run with:  uvicorn app:app --host 0.0.0.0 --port 5000
# Review page: http://localhost:5000

import html
import json
import os
import threading
import uuid
from datetime import datetime

from dotenv import load_dotenv

load_dotenv()  # loads settings from .env

from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from triage import naive_triage, safe_triage

DEFENSES = os.getenv("DEFENSES", "on").lower() == "on"
DB_FILE = "triage_db.json"
lock = threading.Lock()

app = FastAPI()


# ---------- simple storage in a JSON file ----------
def load_items():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE) as f:
        return json.load(f)


def save_items(items):
    with open(DB_FILE, "w") as f:
        json.dump(items, f, indent=2)


def update_item(item_id, **changes):
    with lock:
        items = load_items()
        for item in items:
            if item["id"] == item_id:
                item.update(changes)
        save_items(items)


# ---------- 1. receive the alert from Splunk ----------
@app.post("/alert")
async def receive_alert(request: Request, background_tasks: BackgroundTasks):
    alert = await request.json()
    item = {
        "id": uuid.uuid4().hex[:8],
        "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "alert_name": alert.get("search_name"),
        "fields": alert.get("result", {}),
        "defenses": DEFENSES,
        "status": "triaging",
        "triage": None,
    }
    with lock:
        items = load_items()
        items.append(item)
        save_items(items)

    # Run the AI after we reply, so Splunk doesn't wait
    background_tasks.add_task(run_triage, item["id"], alert)
    print(f"New alert {item['id']}: {item['alert_name']} -> {item['fields']}")
    return {"status": "received", "id": item["id"]}


# ---------- 2. AI triage ----------
def run_triage(item_id, alert):
    try:
        result = safe_triage(alert) if DEFENSES else naive_triage(alert)
        status = "pending_review"
    except Exception as e:
        result = {"verdict": "error", "confidence": None, "note": str(e), "flags": []}
        status = "error"
    update_item(item_id, triage=result, status=status)
    print(f"Triage {item_id}: {result['verdict']}")


# ---------- 3. human approves or rejects ----------
@app.post("/decide/{item_id}/{decision}")
def decide(item_id: str, decision: str):
    if decision in ("approved", "rejected"):
        update_item(item_id, status=decision)
    return RedirectResponse("/", status_code=303)


# ---------- review page ----------
COLORS = {"benign": "#3fb950", "suspicious": "#d29922", "malicious": "#f85149"}


@app.get("/", response_class=HTMLResponse)
def review_page():
    e = html.escape  # Defense 5: escape log data so it can't run as code in the page
    with lock:
        items = list(reversed(load_items()))

    cards = ""
    for it in items:
        t = it.get("triage") or {}
        verdict = t.get("verdict", "...")
        color = COLORS.get(verdict, "#8b949e")
        fields = "".join(f"<div><b>{e(k)}:</b> {e(str(v))}</div>" for k, v in it["fields"].items())
        flags = "".join(f"<li>{e(f)}</li>" for f in t.get("flags", []))
        buttons = ""
        if it["status"] == "pending_review":
            buttons = f"""
              <form method="post" action="/decide/{it['id']}/approved" style="display:inline">
                <button class="ok">Approve</button></form>
              <form method="post" action="/decide/{it['id']}/rejected" style="display:inline">
                <button class="no">Reject</button></form>"""
        cards += f"""
        <div class="card">
          <div class="top">
            <span>{e(it['received_at'])} &middot; {e(it['alert_name'] or '')}</span>
            <span class="tag">defenses {'ON' if it['defenses'] else 'OFF'}</span>
          </div>
          <div class="fields">{fields}</div>
          <div class="verdict" style="color:{color}">
            {e(verdict).upper()} <small>confidence: {e(str(t.get('confidence')))}</small></div>
          <p>{e(t.get('note', ''))}</p>
          {'<ul class="flags">' + flags + '</ul>' if flags else ''}
          <div>Status: <b>{e(it['status'])}</b> {buttons}</div>
        </div>"""

    return f"""<!DOCTYPE html><html><head><title>AI Triage</title>
    <meta http-equiv="refresh" content="10">
    <style>
      body {{ background:#0d1117; color:#c9d1d9; font-family:sans-serif; max-width:800px; margin:auto; padding:20px; }}
      .card {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:16px; margin:12px 0; }}
      .top {{ display:flex; justify-content:space-between; color:#8b949e; font-size:14px; }}
      .tag {{ border:1px solid #30363d; border-radius:4px; padding:0 6px; }}
      .fields {{ font-family:monospace; margin:10px 0; word-break:break-all; }}
      .verdict {{ font-size:20px; font-weight:bold; }}
      .flags {{ color:#d29922; }}
      button {{ border:0; padding:6px 14px; border-radius:6px; cursor:pointer; margin-left:6px; }}
      .ok {{ background:#238636; color:white; }} .no {{ background:#da3633; color:white; }}
    </style></head><body>
    <h1>AI Triage Review</h1>
    <p>Defenses are currently <b>{'ON' if DEFENSES else 'OFF'}</b>. Page refreshes every 10 seconds.</p>
    {cards or '<p>No alerts yet.</p>'}
    </body></html>"""
