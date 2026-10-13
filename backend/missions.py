"""Bounded security missions with persisted evidence, verification and human approval."""
import difflib
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from backend.cloudscan import apply_fix, finding, scan_cloud, summary
from backend.planner import AIPlanner

router = APIRouter(prefix="/missions", tags=["Security missions"])
POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="security-mission")
SLOTS = threading.BoundedSemaphore(2)
DB_LOCK = threading.Lock()
MAX_FILES, MAX_BYTES = 500, 2_000_000
IGNORE = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".cloudguard", "repositories"}
EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".txt", ".env", ".ini", ".cfg", ".conf", ".xml", ".properties", ".tf"}


def now():
    return datetime.now(timezone.utc).isoformat()


def database():
    root = Path(os.getenv("CLOUDGUARD_DATA_DIR", str(Path(__file__).resolve().parents[1] / ".cloudguard")))
    root.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(root / "missions.sqlite3", timeout=20)
    connection.execute("CREATE TABLE IF NOT EXISTS missions (id TEXT PRIMARY KEY, created TEXT NOT NULL, body TEXT NOT NULL)")
    return connection


def save(mission):
    with DB_LOCK, database() as db:
        db.execute("INSERT OR REPLACE INTO missions VALUES (?, ?, ?)", (mission["id"], mission["created_at"], json.dumps(mission)))


def get(mission_id):
    with database() as db:
        row = db.execute("SELECT body FROM missions WHERE id = ?", (mission_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Mission not found")
    return json.loads(row[0])


def event(mission, tool, message, **details):
    mission["events"].append({"sequence": len(mission["events"]) + 1, "at": now(), "tool": tool, "message": message, **details})
    save(mission)


def collect_files(root):
    """Never follow repository symlinks or execute its code. Fail closed on limits."""
    files, errors, total = {}, [], 0
    for directory, dirs, names in os.walk(root, followlinks=False):
        for d in dirs:
            if (Path(directory) / d).is_symlink():
                errors.append({"file": (Path(directory) / d).relative_to(root).as_posix(), "message": "Symlink directory excluded from analysis"})
        dirs[:] = sorted(d for d in dirs if d not in IGNORE and not (Path(directory) / d).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                errors.append({"file": relative, "message": "Symlink excluded from analysis"})
                continue
            if path.suffix.lower() not in EXTENSIONS and name not in {"Dockerfile", ".env"} and not name.endswith(".dockerfile"):
                continue
            if len(files) >= MAX_FILES or path.stat().st_size > 200_000 or total + path.stat().st_size > MAX_BYTES:
                errors.append({"file": relative, "message": "Analysis size limit reached"})
                continue
            try:
                text = path.read_text(encoding="utf-8")
                files[relative] = text
                total += len(text.encode())
            except (UnicodeError, OSError):
                errors.append({"file": relative, "message": "File could not be read as UTF-8"})
    return files, errors


def scan(files):
    # Reuse the original project's scanners on a bounded, symlink-free snapshot.
    from backend.main import scan_for_secrets, scan_source_code, scan_dockerfiles
    result = scan_cloud(files)
    with tempfile.TemporaryDirectory(prefix="cloudguard-scan-") as temp:
        for name, text in files.items():
            dest = Path(temp) / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text)
        for category, items in [("SECRET", scan_for_secrets(temp)), ("CODE", scan_source_code(temp)), ("DOCKER", scan_dockerfiles(temp)["findings"])]:
            for item in items:
                result["findings"].append(finding("CG-" + category + "-" + re.sub(r"\W+", "-", item["type"]).upper(),
                    item["file"], "", item["severity"], item["type"], item["explanation"], item["recommendation"], line=item["line"]))
    result["findings"] = sorted({f["id"]: f for f in result["findings"]}.values(), key=lambda f: (-f["weight"], f["file"], f["id"]))
    # A generated patch must not reproduce a detected credential in its context.
    secret_files = {f["file"] for f in result["findings"] if f["rule"].startswith("CG-SECRET")}
    for item in result["findings"]:
        if item["file"] in secret_files:
            item["fixable"] = False
    return result


def make_patch(before, after):
    return "".join("".join(difflib.unified_diff(before[name].splitlines(True), after[name].splitlines(True),
        fromfile="a/" + name, tofile="b/" + name)) for name in sorted(before) if before[name] != after[name])


def exposure_paths(findings):
    paths = []
    for item in findings:
        if item["rule"] == "CG-AWS-001":
            paths.append({"title": "Internet → administrative ingress → compute access attempt", "finding_ids": [item["id"]],
                          "confidence": "Configuration exposure", "description": "The template permits internet-origin SSH/RDP traffic. Reachability, credentials and an exploit are not established."})
        if item["rule"] == "CG-AWS-004":
            paths.append({"title": "Compromised identity → wildcard permissions → wider impact", "finding_ids": [item["id"]],
                          "confidence": "Conditional scenario", "description": "If this identity is compromised, broad permissions can increase impact. No compromise or trust path has been observed."})
    return paths


def run_mission(mission, files=None, collection_errors=None):
    try:
        mission["status"] = "running"
        event(mission, "collect", "Collecting source without executing repository code.")
        if files is None:
            with tempfile.TemporaryDirectory(prefix="cloudguard-source-") as temp:
                destination = Path(temp) / "repo"
                result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--single-branch", "--", mission["repo_url"], str(destination)], capture_output=True, text=True, timeout=90, env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1"})
                if result.returncode:
                    raise ValueError("GitHub clone failed. Check repository URL and connected Git access.")
                mission["commit"] = subprocess.check_output(["git", "-C", str(destination), "rev-parse", "HEAD"], text=True).strip()
                files, collection_errors = collect_files(destination)
        result = scan(files)
        errors = (collection_errors or []) + result["errors"]
        if not files:
            errors.append({"file": "", "message": "No supported source files found"})
        mission.update(findings=result["findings"], errors=errors, resources=result["resources"],
                       coverage={"files": len(files), "cloudformation_templates": len(result["templates"]),
                                 "checks": ["CloudFormation configuration", "Secret patterns", "Python code patterns", "Dockerfile patterns"],
                                 "not_run": ["Dependency CVE audit", "Live AWS posture", "Runtime exploitability", "Docker build", "Terraform evaluation"]},
                       before=summary(result["findings"], errors), exposure_paths=exposure_paths(result["findings"]))
        mission["source_digest"] = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
        event(mission, "scan", f"Found {len(result['findings'])} findings across {len(files)} files.")
        indexed = {f["id"]: f for f in result["findings"]}
        inspected, staged = set(), set()
        candidate = dict(files)
        ai = AIPlanner(result["findings"]) if mission["planner"] == "ai" else None
        queue = [(action, {"finding_id": f["id"]}) for f in result["findings"] for action in (["inspect_finding", "stage_fix"] if f["fixable"] else ["inspect_finding"])]
        queue.append(("verify_patch", {}))
        budget = 20 if ai else len(queue)
        for turn in range(budget):
            tool, args = ai.next() if ai else queue[turn]
            if tool == "verify_patch" and args == {}:
                break
            if tool not in {"inspect_finding", "stage_fix"} or not isinstance(args, dict) or set(args) != {"finding_id"} or not isinstance(args["finding_id"], str) or args["finding_id"] not in indexed:
                raise ValueError("Planner requested an invalid or unavailable tool")
            item = indexed[args["finding_id"]]
            if tool == "inspect_finding":
                inspected.add(item["id"])
                observation = {"id": item["id"], "recommendation": item["recommendation"], "fixable": item["fixable"]}
                event(mission, tool, item["title"], finding_id=item["id"])
            else:
                if item["id"] not in inspected or item["id"] in staged:
                    raise ValueError("A fix must be inspected first and can only be staged once")
                candidate = apply_fix(candidate, item)
                staged.add(item["id"])
                observation = {"staged": item["id"], "scope": "isolated snapshot"}
                event(mission, tool, "Staged: " + item["title"], finding_id=item["id"])
            if ai:
                ai.observe(observation)
        else:
            if ai:
                event(mission, "budget", "AI tool budget reached; verifying current candidate without additional model calls.")
        verified = scan(candidate)
        after_ids = {f["id"] for f in verified["findings"]}
        resolved = sorted(set(indexed) - after_ids)
        introduced = sorted(after_ids - set(indexed))
        patch = make_patch(files, candidate)
        validation_errors = (collection_errors or []) + verified["errors"]
        if not files:
            validation_errors = errors
        passed = not validation_errors and not introduced and staged.issubset(set(resolved))
        mission.update(after=summary(verified["findings"], validation_errors), remaining_findings=verified["findings"],
                       verification={"passed": passed, "resolved_ids": resolved, "introduced_ids": introduced,
                                     "method": "Rescan of isolated patched snapshot with the same static rules; no cloud deployment or runtime validation.",
                                     "errors": validation_errors},
                       patch=patch, patch_sha256=hashlib.sha256(patch.encode()).hexdigest(),
                       status="awaiting_approval" if patch and passed else "complete" if passed else "needs_review")
        event(mission, "verify_patch", f"Static verification resolved {len(resolved)} finding(s); {len(after_ids)} remain. Production readiness is not established.")
    except Exception as exc:
        mission["status"] = "failed"
        # Never surface provider responses, clone stderr, source contents, or credentials.
        mission["error"] = str(exc) if isinstance(exc, ValueError) else f"Mission stopped ({type(exc).__name__}). Check provider access or retry with the policy planner."
        event(mission, "error", mission["error"])
    finally:
        mission["finished_at"] = now()
        save(mission)


class MissionRequest(BaseModel):
    source: Literal["demo", "github"] = "demo"
    repo_url: str = Field(default="", max_length=300)
    planner: Literal["policy", "ai"] = "policy"


@router.get("/capabilities")
def capabilities():
    return {"ai_available": bool(os.getenv("CLOUDGUARD_AI_KEY")), "ai_model": os.getenv("CLOUDGUARD_AI_MODEL", "gpt-4.1-mini"),
            "policy_available": True, "deployment_enabled": os.getenv("CLOUDGUARD_ENABLE_DEPLOYMENT") == "1"}


@router.get("")
def list_missions():
    with database() as db:
        rows = db.execute("SELECT body FROM missions ORDER BY created DESC LIMIT 20").fetchall()
    return [{k: m.get(k) for k in ("id", "created_at", "status", "repository", "planner", "before", "after")} for m in (json.loads(row[0]) for row in rows)]


@router.post("", status_code=202)
def create_mission(request: MissionRequest):
    if request.planner == "ai" and not os.getenv("CLOUDGUARD_AI_KEY"):
        raise HTTPException(409, "AI planner is not configured. Use the policy planner, or configure CLOUDGUARD_AI_KEY securely.")
    if request.source == "github" and not re.fullmatch(r"https://github\.com/[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+(?:\.git)?/?", request.repo_url):
        raise HTTPException(422, "Provide an HTTPS GitHub repository URL without query parameters or credentials.")
    if not SLOTS.acquire(blocking=False):
        raise HTTPException(429, "Two missions are already running. Retry when one finishes.")
    mission = {"id": uuid.uuid4().hex, "created_at": now(), "status": "queued", "source": request.source,
               "planner": request.planner, "repo_url": request.repo_url if request.source == "github" else "",
               "repository": request.repo_url.removeprefix("https://github.com/").rstrip("/") if request.source == "github" else "CloudGuard / AWS deployment lab",
               "events": [], "findings": [], "commit": None}
    def work():
        try:
            if request.source == "demo":
                files, errors = collect_files(Path(__file__).parent / "demo")
                run_mission(mission, files, errors)
            else:
                run_mission(mission)
        finally:
            SLOTS.release()
    try:
        save(mission)
        POOL.submit(work)
    except Exception:
        SLOTS.release()
        raise
    return {"id": mission["id"], "status": "queued"}


@router.get("/{mission_id}")
def read_mission(mission_id: str):
    return get(mission_id)


class Approval(BaseModel):
    patch_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


@router.post("/{mission_id}/approve")
def approve(mission_id: str, request: Approval):
    with DB_LOCK:
        mission = get(mission_id)
        if mission["status"] == "approved" and request.patch_sha256 == mission["patch_sha256"]:
            return mission
        if mission["status"] != "awaiting_approval" or request.patch_sha256 != mission.get("patch_sha256"):
            raise HTTPException(409, "Only the current verified patch can be approved.")
        mission["status"] = "approved"
        mission["approved_at"] = now()
        mission["events"].append({"sequence": len(mission["events"]) + 1, "at": now(), "tool": "human_approval", "message": "Reviewer approved this patch for export. No repository or AWS resources were modified."})
        with database() as db:
            db.execute("UPDATE missions SET body = ? WHERE id = ?", (json.dumps(mission), mission_id))
    return mission


@router.get("/{mission_id}/patch")
def download_patch(mission_id: str):
    mission = get(mission_id)
    if mission["status"] != "approved":
        raise HTTPException(409, "Review and approve the verified patch before exporting it.")
    return Response(mission["patch"], media_type="text/x-diff", headers={"Content-Disposition": f'attachment; filename="cloudguard-{mission["id"][:8]}.patch"'})


@router.get("/{mission_id}/report")
def report(mission_id: str):
    mission = get(mission_id)
    mission.pop("patch", None)
    return Response(json.dumps(mission, indent=2), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="cloudguard-{mission["id"][:8]}.json"'})
