from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..attack_surface_graph.graph import build


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


class MissingAssessment(Exception):
    pass


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        os.close(descriptor)
        path.chmod(0o600)
        self.path = path
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
            CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS evidence(id TEXT PRIMARY KEY, assessment TEXT NOT NULL, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events(sequence INTEGER PRIMARY KEY AUTOINCREMENT, assessment TEXT NOT NULL, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS assets(id TEXT NOT NULL, assessment TEXT NOT NULL, kind TEXT NOT NULL, document TEXT NOT NULL, PRIMARY KEY(id,assessment));
            CREATE TABLE IF NOT EXISTS edges(id TEXT NOT NULL, assessment TEXT NOT NULL, document TEXT NOT NULL, PRIMARY KEY(id,assessment));
            CREATE TABLE IF NOT EXISTS ports(assessment TEXT NOT NULL,target TEXT NOT NULL,port INTEGER NOT NULL,protocol TEXT NOT NULL,state TEXT NOT NULL,status TEXT NOT NULL,document TEXT NOT NULL,PRIMARY KEY(assessment,target,port,protocol));
            CREATE INDEX IF NOT EXISTS event_assessment ON events(assessment,sequence);
            CREATE INDEX IF NOT EXISTS port_assessment ON ports(assessment,protocol,port);
            CREATE INDEX IF NOT EXISTS evidence_assessment ON evidence(assessment);
            """)
            db.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
            for migration in sorted((Path(__file__).parent / "migrations").glob("*.sql")):
                if not db.execute("SELECT 1 FROM schema_migrations WHERE version=?", (migration.name,)).fetchone():
                    db.executescript(migration.read_text())
                    db.execute("INSERT OR IGNORE INTO schema_migrations VALUES (?,?)", (migration.name, timestamp()))

    def connection(self):
        return sqlite3.connect(self.path, timeout=30)

    def save(self, document: dict) -> None:
        with self.connection() as db:
            db.execute("INSERT OR REPLACE INTO assessments VALUES (?,?)", (document["id"], json.dumps(document)))

    def assessment(self, identifier: str) -> dict:
        with self.connection() as db:
            row = db.execute("SELECT document FROM assessments WHERE id=?", (identifier,)).fetchone()
        if row is None:
            raise MissingAssessment(identifier)
        return json.loads(row[0])

    def list(self) -> list[dict]:
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT document FROM assessments ORDER BY rowid DESC LIMIT 100")]

    def event(self, identifier: str, agent: str, message: str, data: dict | None = None) -> int:
        document = {"timestamp": timestamp(), "agent": agent, "message": message, "data": data or {}}
        with self.connection() as db:
            cursor = db.execute("INSERT INTO events(assessment,document) VALUES (?,?)", (identifier, json.dumps(document)))
            return cursor.lastrowid

    def events(self, identifier: str, after: int = 0, limit: int = 500) -> list[dict]:
        with self.connection() as db:
            rows = db.execute("SELECT sequence,document FROM events WHERE assessment=? AND sequence>? ORDER BY sequence LIMIT ?", (identifier, after, limit))
            return [{"sequence": row[0], **json.loads(row[1])} for row in rows]

    def capture(self, identifier: str, source: str, mode: str, observation: dict) -> str:
        document = {"timestamp": timestamp(), "source": source, "mode": mode, "observation": observation}
        digest = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
        document.update(id=digest, sha256=digest)
        with self.connection() as db:
            db.execute("INSERT INTO evidence VALUES (?,?,?)", (digest, identifier, json.dumps(document)))
        return digest

    def evidence(self, identifier: str) -> list[dict]:
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT document FROM evidence WHERE assessment=?", (identifier,))]

    def asset(self, identifier: str, kind: str, name: str, evidence: str, attributes: dict | None = None,
              inferred: bool = False, confidence: float = 1) -> str:
        key = hashlib.sha256(f"{kind}:{name}".encode()).hexdigest()[:24]
        document = {"id": key, "kind": kind, "name": name, "attributes": attributes or {},
                    "inferred": inferred, "confidence": confidence, "evidence_refs": [evidence],
                    "assessment_id": identifier, "discovered_at": timestamp(), "last_observed_at": timestamp(),
                    "discovery_status": "inferred" if inferred else "observed", "source": evidence}
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT document FROM assets WHERE id=? AND assessment=?", (key, identifier)).fetchone()
            if prior:
                old = json.loads(prior[0])
                document["discovered_at"] = old.get("discovered_at", document["discovered_at"])
                document["evidence_refs"] = sorted(set(old["evidence_refs"] + [evidence]))
                document["attributes"] = ({**document["attributes"], **old["attributes"]}
                                          if not old["inferred"] and inferred
                                          else {**old["attributes"], **document["attributes"]})
                if not old["inferred"]:
                    document["inferred"] = False
                document["confidence"] = max(old["confidence"], confidence)
                document["discovery_status"] = "inferred" if document["inferred"] else "observed"
            db.execute("INSERT OR REPLACE INTO assets VALUES (?,?,?,?)", (key, identifier, kind, json.dumps(document)))
        return key

    def record(self, identifier: str, category: str, key: str, document: dict, source: str,
               evidence_refs: list[str], status: str = "analysed") -> None:
        now = timestamp()
        with self.connection() as db:
            old = db.execute("SELECT discovered_at FROM intelligence_records WHERE assessment=? AND category=? AND id=?",
                             (identifier, category, key)).fetchone()
            created = old[0] if old else now
            document = {**document, "id": key, "assessment_id": identifier, "source": source,
                        "discovered_at": created, "last_observed_at": now, "status": status,
                        "evidence_refs": evidence_refs}
            db.execute("INSERT OR REPLACE INTO intelligence_records VALUES (?,?,?,?,?,?,?,?)",
                       (identifier, category, key, status, source, created, now, json.dumps(document)))

    def records(self, identifier: str, category: str, offset: int = 0, limit: int = 500) -> list[dict]:
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT document FROM intelligence_records WHERE assessment=? AND category=? ORDER BY id LIMIT ? OFFSET ?",
                (identifier, category, limit, offset))]

    def record_counts(self, identifier: str, category: str) -> dict:
        with self.connection() as db:
            return {row[0]: row[1] for row in db.execute(
                "SELECT status,count(*) FROM intelligence_records WHERE assessment=? AND category=? GROUP BY status",
                (identifier, category))}

    def execution_start(self, identifier: str, agent: str, skill: str, tool: str, target: str) -> str:
        key = str(uuid.uuid4())
        document = {"id": key, "assessment_id": identifier, "agent": agent, "skill": skill,
                    "tool": tool, "target": target, "started_at": timestamp(), "status": "running"}
        with self.connection() as db:
            db.execute("INSERT INTO executions VALUES (?,?,?,?,?,?,?)",
                       (key, identifier, agent, skill, tool, "running", json.dumps(document)))
        self.event(identifier, agent, "Skill execution started", document)
        return key

    def execution_finish(self, key: str, status: str, evidence_refs: list[str] | None = None, error: str = "") -> None:
        with self.connection() as db:
            row = db.execute("SELECT document FROM executions WHERE id=?", (key,)).fetchone()
            if row is None:
                raise ValueError("Execution record not found")
            document = json.loads(row[0])
            document.update(status=status, finished_at=timestamp(), evidence_refs=evidence_refs or [], error=error)
            db.execute("UPDATE executions SET status=?,document=? WHERE id=?", (status, json.dumps(document), key))
        self.event(document["assessment_id"], document["agent"], "Skill execution finished", document)

    def executions(self, identifier: str, offset: int = 0, limit: int = 500) -> list[dict]:
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute(
                "SELECT document FROM executions WHERE assessment=? ORDER BY rowid LIMIT ? OFFSET ?",
                (identifier, limit, offset))]

    def assets(self, identifier: str) -> list[dict]:
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute("SELECT document FROM assets WHERE assessment=? ORDER BY kind,id", (identifier,))]

    def edge(self, identifier: str, source: str, target: str, relation: str, evidence: str, inferred: bool, confidence: float):
        document = {"source": source, "target": target, "relation": relation, "evidence_refs": [evidence],
                    "inferred": inferred, "confidence": confidence}
        key = hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest()
        with self.connection() as db:
            db.execute("INSERT OR REPLACE INTO edges VALUES (?,?,?)", (key, identifier, json.dumps(document)))

    def graph(self, identifier: str) -> dict:
        with self.connection() as db:
            edges = [json.loads(row[0]) for row in db.execute("SELECT document FROM edges WHERE assessment=?", (identifier,))]
        return build(self.assets(identifier), edges)

    def seed_ports(self, identifier: str, targets: list[str], protocols: list[str]) -> None:
        with self.connection() as db:
            db.executemany("INSERT OR IGNORE INTO ports VALUES (?,?,?,?,?,?,?)", (
                (identifier, target, port, protocol, "unknown", "pending",
                 json.dumps({"target": target, "port": port, "protocol": protocol, "state": "unknown",
                             "service": "unknown", "product": "", "version": "", "fingerprint_confidence": 0,
                             "evidence_refs": [], "timestamp": timestamp(), "assessment_status": "pending"}))
                for target in targets for protocol in protocols for port in range(1, 65536)
            ))

    def ports_batch(self, identifier: str, records: list[dict]) -> None:
        with self.connection() as db:
            db.executemany("UPDATE ports SET state=?,status=?,document=? WHERE assessment=? AND target=? AND port=? AND protocol=?", (
                (item["state"], item["assessment_status"], json.dumps(item), identifier,
                 item["target"], item["port"], item["protocol"]) for item in records
            ))
            db.executemany("INSERT INTO events(assessment,document) VALUES (?,?)", (
                (identifier, json.dumps({"timestamp": item["timestamp"], "agent": "port_discovery",
                                         "message": "port", "data": item})) for item in records
            ))

    def ports(self, identifier: str, offset: int = 0, limit: int = 500, state: str | None = None) -> list[dict]:
        query = "SELECT document FROM ports WHERE assessment=?"
        args: list = [identifier]
        if state:
            query += " AND state=?"
            args.append(state)
        query += " ORDER BY target,protocol,port LIMIT ? OFFSET ?"
        args.extend([limit, offset])
        with self.connection() as db:
            return [json.loads(row[0]) for row in db.execute(query, args)]

    def coverage(self, identifier: str) -> dict:
        with self.connection() as db:
            counts = {row[0]: row[1] for row in db.execute("SELECT status,count(*) FROM ports WHERE assessment=? GROUP BY status", (identifier,))}
            states = {row[0]: row[1] for row in db.execute("SELECT state,count(*) FROM ports WHERE assessment=? GROUP BY state", (identifier,))}
        total = sum(counts.values())
        completed = counts.get("completed", 0)
        return {"total_ports": total, "completed_ports": completed, "uncompleted_ports": total - completed,
                "statuses": counts, "states": states, "security_pass": False}

    def interrupt(self, identifier: str, status: str) -> None:
        with self.connection() as db:
            db.execute("""UPDATE ports SET status=?, document=json_set(document,
                       '$.assessment_status', ?, '$.timestamp', ?)
                       WHERE assessment=? AND status='pending'""", (status, status, timestamp(), identifier))
        for execution in self.executions(identifier, limit=100000):
            if execution["status"] == "running":
                self.execution_finish(execution["id"], status, error="Execution interrupted before completion")

    def recover(self) -> None:
        with self.connection() as db:
            documents = [json.loads(row[0]) for row in db.execute(
                "SELECT document FROM assessments WHERE json_extract(document,'$.status') IN ('queued','running')")]
        for document in documents:
            if document["status"] in {"queued", "running"}:
                document["status"] = "interrupted"
                document["limitations"].append("Engine restarted; incomplete execution was not resumed or marked passed.")
                self.interrupt(document["id"], "interrupted")
                self.save(document)
