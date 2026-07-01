import hashlib
import hmac
import json
import os
import logging
import asyncio

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request, HTTPException
from github import Github

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("github-webhook")

app = FastAPI(title="Bug Triage GitHub Webhook Receiver")

LEMMA_API_URL = os.getenv("LEMMA_API_URL", "https://api.lemma.work")
LEMMA_POD_ID = os.getenv("LEMMA_POD_ID")
LEMMA_TOKEN = os.getenv("LEMMA_TOKEN")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "").encode()

HEADERS = {"Authorization": f"Bearer {LEMMA_TOKEN}", "Content-Type": "application/json"}


def verify_signature(payload: bytes, signature_header: str | None) -> bool:
    if not GITHUB_WEBHOOK_SECRET:
        return True
    if not signature_header:
        return False
    expected = "sha256=" + hmac.new(GITHUB_WEBHOOK_SECRET, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_header)


async def call_lemma_agent(title: str, description: str) -> dict:
    message_text = f"Title: {title}\nDescription: {description}"

    async with httpx.AsyncClient(timeout=120) as client:
        r1 = await client.post(
            f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations",
            headers=HEADERS,
            json={"agent_name": "bug_triage_agent"},
        )
        if r1.status_code not in (200, 201):
            raise RuntimeError(f"Create conversation failed: {r1.status_code} {r1.text}")
        conv_id = r1.json().get("id")
        if not conv_id:
            raise RuntimeError("No conversation id")

        r2 = await client.post(
            f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations/{conv_id}/messages",
            headers=HEADERS,
            json={"content": message_text},
        )
        logger.info(f"Send message: {r2.status_code}")
        if r2.status_code not in (200, 201):
            raise RuntimeError(f"Send message failed: {r2.status_code} {r2.text}")

        for attempt in range(15):
            await asyncio.sleep(2)
            r3 = await client.get(
                f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/conversations/{conv_id}/messages",
                headers=HEADERS,
            )
            if r3.status_code == 200:
                msgs = r3.json().get("items", [])
                for m in reversed(msgs):
                    if m.get("role") == "assistant":
                        content = m.get("content", "").strip()
                        if content:
                            try:
                                parsed = json.loads(content)
                                parsed["conversation_id"] = str(conv_id)
                                return parsed
                            except (json.JSONDecodeError, TypeError):
                                return {"raw": content, "conversation_id": str(conv_id)}
        raise RuntimeError("Agent did not respond within timeout")


async def save_to_issues_table(triage: dict, raw_input: str, source: str):
    similar = triage.get("similar_issues", [])
    if isinstance(similar, list):
        similar = json.dumps(similar)
    elif similar is None:
        similar = ""
    async with httpx.AsyncClient(timeout=30) as client:
        payload = {
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
        resp = await client.post(
            f"{LEMMA_API_URL}/pods/{LEMMA_POD_ID}/datastore/tables/issues/records",
            headers=HEADERS,
            json=payload,
        )
        if resp.status_code not in (200, 201):
            logger.error(f"Save records error: {resp.status_code} {resp.text}")


def post_github_comment(repo_full_name: str, issue_number: int, triage: dict):
    if not GITHUB_TOKEN:
        logger.warning("No GITHUB_TOKEN set -- skipping comment")
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
    logger.info(f"Comment posted on {repo_full}#{issue_number}")


@app.get("/")
async def root():
    return {"status": "ok", "service": "bug-triage-github-webhook"}


@app.get("/webhook/github")
async def webhook_get():
    return {"status": "ok", "message": "GitHub webhook endpoint ready"}


@app.post("/webhook/github")
async def github_webhook(request: Request):
    payload = await request.body()
    signature = request.headers.get("x-hub-signature-256")

    if not verify_signature(payload, signature):
        raise HTTPException(401, "Invalid signature")

    event = request.headers.get("x-github-event", "")

    if event == "ping":
        return {"status": "pong"}

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

    logger.info(f"[Webhook] Received issue from {repo_full}#{issue_num}: {title}")
    logger.info("[Webhook] Forwarding to Bug Triage Agent...")

    try:
        triage = await call_lemma_agent(title, description)
    except Exception as e:
        logger.error(f"[Webhook] Agent call failed: {e}")
        return {"status": "error", "message": str(e)}

    logger.info("[Webhook] Triage result received")

    await save_to_issues_table(triage, f"Title: {title}\nDescription: {description}", "github")
    post_github_comment(repo_full, issue_num, triage)

    logger.info(f"Priority: {triage.get('priority')} | Area: {triage.get('affected_area')}")

    return {"status": "processed", "triage": triage}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))
