import hashlib
import hmac
import json
import os
import logging

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from github import Github

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("github-webhook")

app = FastAPI(title="Bug Triage GitHub Webhook Receiver")

LEMMA_API_URL = os.getenv("LEMMA_API_URL", "https://api.lemma.work")
LEMMA_ORG_ID = os.getenv("LEMMA_ORG_ID")
LEMMA_POD_ID = os.getenv("LEMMA_POD_ID")
LEMMA_TOKEN = os.getenv("LEMMA_TOKEN")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()

HEADERS = {"Authorization": f"Bearer {LEMMA_TOKEN}", "Content-Type": "application/json"}


def verify_signature(payload: bytes, signature_header: str | None) -> bool:
    if not GITHUB_WEBHOOK_SECRET:
        return True
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(GITHUB_WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def parse_sse_events(response: httpx.Response) -> list[dict]:
    events = []
    data_lines = []
    for line in response.iter_lines():
        line = line.strip()
        if line == "":
            if data_lines:
                raw = "".join(data_lines)
                data_lines = []
                if raw:
                    try:
                        events.append(json.loads(raw))
                    except json.JSONDecodeError:
                        pass
        elif line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        raw = "".join(data_lines)
        if raw:
            try:
                events.append(json.loads(raw))
            except json.JSONDecodeError:
                pass
    return events


async def call_lemma_agent(title: str, description: str) -> dict:
    message_text = f"Title: {title}\nDescription: {description}"

    async with httpx.AsyncClient(timeout=30) as client:
        create_resp = await client.post(
            f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations",
            headers=HEADERS,
            json={"agent_name": "bug_triage_agent"},
        )
        if create_resp.status_code not in (200, 201):
            logger.error(f"Conversation create error: {create_resp.status_code} {create_resp.text}")
            raise HTTPException(502, "Failed to create conversation")
        conv = create_resp.json()
        conv_id = conv.get("id")
        if not conv_id:
            raise HTTPException(502, "No conversation id returned")

        body = {"content": message_text}
        send_resp = await client.post(
            f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations/{conv_id}/messages",
            headers=HEADERS,
            json=body,
            timeout=120,
        )
        if send_resp.status_code not in (200, 201):
            logger.error(f"Message send error: {send_resp.status_code} {send_resp.text}")
            raise HTTPException(502, "Failed to send message")

        events = parse_sse_events(send_resp)
        assistant_content = None
        for ev in events:
            ev_type = ev.get("type") or ev.get("event", "")
            ev_data = ev.get("data", {})
            if ev_type == "message" and isinstance(ev_data, dict):
                if ev_data.get("role") == "assistant":
                    assistant_content = ev_data.get("content", "")
            elif ev_type == "completed":
                break

        if assistant_content:
            try:
                parsed = json.loads(assistant_content)
                parsed["conversation_id"] = str(conv_id)
                return parsed
            except (json.JSONDecodeError, TypeError):
                return {"raw": assistant_content, "conversation_id": str(conv_id)}

        list_resp = await client.get(
            f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations/{conv_id}/messages",
            headers=HEADERS,
            timeout=30,
        )
        if list_resp.status_code == 200:
            msgs = list_resp.json()
            for m in msgs.get("items", []):
                if m.get("role") == "assistant":
                    content = m.get("content", "")
                    try:
                        parsed = json.loads(content)
                        parsed["conversation_id"] = str(conv_id)
                        return parsed
                    except (json.JSONDecodeError, TypeError):
                        return {"raw": content, "conversation_id": str(conv_id)}

        return {"error": "no assistant response", "conversation_id": str(conv_id)}


async def save_to_issues_table(triage: dict, raw_input: str, source: str):
    similar = triage.get("similar_issues", [])
    if isinstance(similar, list):
        similar = json.dumps(similar)
    else:
        similar = str(similar) if similar else ""
    record = {
        "data": {
            "title": triage.get("title", raw_input[:80]),
            "raw_input": raw_input,
            "source": source,
            "priority": triage.get("priority", "P3"),
            "priority_rationale": triage.get("priority_rationale", ""),
            "affected_area": triage.get("affected_area", ""),
            "steps_to_reproduce": triage.get("steps_to_reproduce", ""),
            "status": "open",
            "duplicate_of": triage.get("duplicate_of"),
            "similar_issues": similar,
            "confidence": str(triage.get("confidence", "")),
            "conversation_id": triage.get("conversation_id", ""),
        }
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/datastore/tables/issues/records",
            headers=HEADERS,
            json=record,
        )
        if resp.status_code not in (200, 201):
            logger.error(f"Failed to save record: {resp.status_code} {resp.text}")


def post_github_comment(repo_full_name: str, issue_number: int, triage: dict):
    if not GITHUB_TOKEN:
        logger.warning("No GITHUB_TOKEN set, skipping comment")
        return
    g = Github(GITHUB_TOKEN)
    repo = g.get_repo(repo_full_name)
    issue = repo.get_issue(issue_number)

    similar = triage.get("similar_issues", [])
    similar_text = json.dumps(similar, indent=2) if similar else "None"
    body = (
        f"### Bug Triage Report\n\n"
        f"**Priority:** {triage.get('priority', 'N/A')}\n"
        f"**Affected Area:** {triage.get('affected_area', 'N/A')}\n"
        f"**Confidence:** {triage.get('confidence', 'N/A')}\n\n"
        f"**Rationale:**\n{triage.get('priority_rationale', 'N/A')}\n\n"
        f"**Steps to Reproduce:**\n{triage.get('steps_to_reproduce', 'N/A')}\n\n"
        f"**Duplicate of:** {triage.get('duplicate_of', 'None')}\n"
        f"**Similar issues:** {similar_text}\n"
    )
    issue.create_comment(body)
    logger.info(f"Posted comment on {repo_full_name}#{issue_number}")


# Add this right before the POST handler:
@app.get("/webhook/github")
async def github_webhook_verify():
    return {"status": "ok", "message": "GitHub webhook endpoint ready"}
    

@app.post("/webhook/github")
async def github_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("x-hub-signature-256")

    if not verify_signature(payload, signature):
        raise HTTPException(401, "Invalid signature")

    event = request.headers.get("x-github-event", "")

    if event == "ping":
        return {"status": "pong", "event": "ping"}
        
    if event not in ("issues", "issue_comment"):
        return {"status": "ignored", "event": event}

    data = json.loads(payload)
    action = data.get("action", "")
    issue = data.get("issue", {})
    repo = data.get("repository", {})

    if action not in ("opened", "created"):
        return {"status": "ignored", "action": action}

    title = issue.get("title", "Untitled")
    description = issue.get("body", "") or issue.get("title", "")
    repo_full = repo.get("full_name", "unknown/repo")
    issue_num = issue.get("number", 0)

    logger.info(f"[Webhook] Received issue from {repo_full}#{issue_num}: \"{title}\"")
    logger.info(f"[Webhook] Forwarding to Bug Triage Agent...")

    triage = await call_lemma_agent(title, description)

    logger.info(f"[Webhook] Triage result received!")

    await save_to_issues_table(triage, f"Title: {title}\nDescription: {description}", "github")

    if "error" not in triage:
        post_github_comment(repo_full, issue_num, triage)

    logger.info(
        f"--- Response ---\n"
        f"Priority: {triage.get('priority')} | Area: {triage.get('affected_area')} | "
        f"Confidence: {triage.get('confidence')}"
    )

    return {"status": "processed", "triage": triage}
