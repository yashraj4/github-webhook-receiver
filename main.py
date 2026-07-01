import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from github import Github
import httpx

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("github-webhook")

app = FastAPI(title="Bug Triage GitHub Webhook Receiver")

LEMMA_API_URL = os.getenv("LEMMA_API_URL", "https://api.lemma.work")
LEMMA_POD_ID = os.getenv("LEMMA_POD_ID")
LEMMA_REFRESH_TOKEN = os.getenv("LEMMA_REFRESH_TOKEN", "")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()

executor = ThreadPoolExecutor(max_workers=4)

_current_token = os.getenv("LEMMA_TOKEN", "")


def refresh_lemma_token():
    global _current_token
    if not LEMMA_REFRESH_TOKEN:
        logger.warning("No LEMMA_REFRESH_TOKEN set - using LEMMA_TOKEN as-is")
        return _current_token
    try:
        r = httpx.post(
            f"{LEMMA_API_URL}/auth/cli/refresh",
            json={"refresh_token": LEMMA_REFRESH_TOKEN},
            timeout=15,
        )
        if r.status_code >= 400:
            logger.error(f"Token refresh failed: {r.status_code} {r.text[:200]}")
            return _current_token
        data = r.json()
        _current_token = data.get("access_token", data.get("token", _current_token))
        logger.info("Token refreshed successfully")
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
    return _current_token


def get_token():
    if not _current_token:
        refresh_lemma_token()
    return _current_token


def headers():
    return {"Authorization": f"Bearer {get_token()}", "Content-Type": "application/json"}


def verify_signature(payload: bytes, signature_header: str | None) -> bool:
    if not GITHUB_WEBHOOK_SECRET:
        return True
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(GITHUB_WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


def call_lemma_agent(title: str, description: str) -> dict:
    msg_text = f"Title: {title}\nDescription: {description}"
    with httpx.Client(timeout=120) as c:
        h = headers()
        r1 = c.post(f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations",
                     headers=h, json={"agent_name": "bug_triage_agent"})
        if r1.status_code == 401:
            logger.info("Token expired, refreshing...")
            refresh_lemma_token()
            h = headers()
            r1 = c.post(f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations",
                         headers=h, json={"agent_name": "bug_triage_agent"})
        conv_id = r1.json().get("id")
        logger.info(f"Conversation: {conv_id}")

        agent_run_id = None
        with c.stream("POST", f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations/{conv_id}/messages",
                       headers=h, json={"content": msg_text}) as resp:
            buf = []
            for line in resp.iter_lines():
                line = line.strip()
                if line == "" and buf:
                    raw = "".join(buf)
                    buf = []
                    try:
                        ev = json.loads(raw)
                        if ev.get("agent_run_id"):
                            agent_run_id = ev["agent_run_id"]
                        if ev.get("type") == "completed":
                            break
                    except json.JSONDecodeError:
                        pass
                elif line.startswith("data:"):
                    buf.append(line[5:].lstrip())

        if not agent_run_id:
            raise RuntimeError("No agent_run_id")

        with c.stream("GET", f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations/{conv_id}/stream?agent_run_id={agent_run_id}",
                       headers=h) as resp:
            for line in resp.iter_lines():
                pass

        time.sleep(3)
        for attempt in range(10):
            r3 = c.get(f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations/{conv_id}/messages?limit=20",
                        headers=h)
            items = r3.json().get("items", [])
            for m in reversed(items):
                role = m.get("role")
                content = m.get("content", m.get("text", ""))
                if role == "assistant" and content:
                    match = re.search(r"```json\s*(\{.*?\})\s*```", content, re.DOTALL)
                    if not match:
                        match = re.search(r"(\{.*\})", content, re.DOTALL)
                    clean = match.group(1) if match else content.strip()
                    try:
                        parsed = json.loads(clean)
                        parsed["conversation_id"] = str(conv_id)
                        return parsed
                    except (json.JSONDecodeError, TypeError):
                        logger.info(f"Assistant content not JSON: {content[:100]}")
            time.sleep(3)

        raise RuntimeError("Agent did not return valid JSON")


def save_to_issues_table(triage: dict, raw_input: str, source: str):
    similar = triage.get("similar_issues", [])
    similar = json.dumps(similar) if isinstance(similar, list) and similar else ""
    with httpx.Client(timeout=30) as c:
        h = headers()
        payload = {"data": {
            "title": triage.get("title", raw_input[:80]),
            "raw_input": raw_input, "source": source,
            "priority": triage.get("priority", "P3"),
            "priority_rationale": triage.get("priority_rationale", ""),
            "affected_area": triage.get("affected_area", ""),
            "steps_to_reproduce": triage.get("steps_to_reproduce", ""),
            "status": "open",
            "duplicate_of": triage.get("duplicate_of"),
            "similar_issues": similar,
            "confidence": str(triage.get("confidence", "")),
            "conversation_id": triage.get("conversation_id", ""),
        }}
        r = c.post(f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/datastore/tables/issues/records",
                    headers=h, json=payload)
        if r.status_code not in (200, 201):
            logger.error(f"Save error: {r.status_code} {r.text[:200]}")


def post_github_comment(repo_full_name: str, issue_number: int, triage: dict):
    if not GITHUB_TOKEN:
        logger.warning("No GITHUB_TOKEN set - skipping comment")
        return
    try:
        g = Github(GITHUB_TOKEN)
        repo = g.get_repo(repo_full_name)
        issue = repo.get_issue(issue_number)
        body = (
            f"### Bug Triage Report\n\n"
            f"**Priority:** {triage.get('priority', 'N/A')}\n"
            f"**Affected Area:** {triage.get('affected_area', 'N/A')}\n"
            f"**Confidence:** {triage.get('confidence', 'N/A')}\n\n"
            f"**Rationale:**\n{triage.get('priority_rationale', 'N/A')}\n\n"
            f"**Steps to Reproduce:**\n{triage.get('steps_to_reproduce', 'N/A')}\n\n"
            f"**Duplicate of:** {triage.get('duplicate_of', 'None')}\n"
        )
        issue.create_comment(body)
        logger.info(f"Comment posted on {repo_full_name}#{issue_number}")
    except Exception as e:
        logger.error(f"GitHub comment failed: {e}")


async def process_issue(repo_full: str, issue_num: int, title: str, body: str):
    try:
        logger.info(f"Processing {repo_full}#{issue_num}...")
        triage = await asyncio.get_event_loop().run_in_executor(
            executor, call_lemma_agent, title, body)
        logger.info(f"Triage done: P={triage.get('priority')}")
        await asyncio.get_event_loop().run_in_executor(
            executor, save_to_issues_table, triage,
            f"Title: {title}\nDescription: {body}", "github")
        await asyncio.get_event_loop().run_in_executor(
            executor, post_github_comment, repo_full, issue_num, triage)
        logger.info(f"Done processing {repo_full}#{issue_num}")
    except Exception as e:
        logger.error(f"Failed to process {repo_full}#{issue_num}: {e}", exc_info=True)


@app.get("/")
async def root():
    return {"status": "ok"}


@app.get("/webhook/github")
async def webhook_get():
    return {"status": "ok"}


@app.post("/webhook/github")
async def github_webhook(request: Request):
    payload = await request.body()
    sig = request.headers.get("x-hub-signature-256")
    if not verify_signature(payload, sig):
        raise HTTPException(401, "Invalid signature")

    event = request.headers.get("x-github-event", "")
    if event == "ping":
        return {"status": "pong"}
    if event not in ("issues", "issue_comment"):
        return {"status": "ignored", "event": event}

    data = json.loads(payload)
    action = data.get("action", "")
    if action not in ("opened", "created"):
        return {"status": "ignored", "action": action}

    issue = data.get("issue", {})
    repo = data.get("repository", {})
    title = issue.get("title", "Untitled")
    description = issue.get("body", "") or issue.get("title", "")
    repo_full = repo.get("full_name", "unknown/repo")
    issue_num = issue.get("number", 0)

    logger.info(f"Webhook received: {repo_full}#{issue_num} - {title}")

    asyncio.ensure_future(process_issue(repo_full, issue_num, title, description))

    return {"status": "accepted", "message": "Processing in background"}


if __name__ == "__main__":
    refresh_lemma_token()
    import uvicorn
    uvicorn.run(app, host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
