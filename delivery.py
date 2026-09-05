"""Durable send journal. An uncertain request is never automatically resent."""

import contextlib
import hashlib
import json
import os
import sqlite3
import stat
import fcntl
from pathlib import Path


@contextlib.contextmanager
def journal(key_file):
    directory = Path(key_file).parent / ".agent-state"
    directory.mkdir(mode=0o700, exist_ok=True)
    mode = directory.lstat().st_mode
    if not stat.S_ISDIR(mode) or stat.S_IMODE(mode) & 0o077:
        raise ValueError("journal directory must be private and not a symlink")
    path = directory / "delivery.sqlite3"
    lock_fd = os.open(str(directory / 'delivery.lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        raise ValueError('another delivery operation is running') from None
    connection = None
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("journal file must be private and regular")
        finally:
            os.close(fd)
        connection = sqlite3.connect(str(path), timeout=2)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE IF NOT EXISTS deliveries "
                           "(id TEXT PRIMARY KEY, origin TEXT, room TEXT, did TEXT, "
                           "nonce TEXT, text TEXT, state TEXT, record TEXT)")
        connection.commit()
        yield connection
    finally:
        if connection is not None:
            connection.close()
        os.close(lock_fd)


def deliver(key_file, origin, room, did, nonce, text, request, verify):
    from agent import validate_base_url
    origin = validate_base_url(origin)
    identifier = hashlib.sha256(json.dumps(
        [origin, room, did, text], ensure_ascii=False
    ).encode()).hexdigest()
    with journal(key_file) as db:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM deliveries WHERE id=?", (identifier,)).fetchone():
            raise ValueError("delivery already recorded; use receipt or reconcile, never blind retry")
        if db.execute("SELECT 1 FROM deliveries WHERE origin=? AND did=? AND state='unknown'",
                      (origin, did)).fetchone():
            raise ValueError("identity has an unresolved delivery; reconcile before another send")
        # Persist BEFORE network I/O. A crash at any later point is an unknown outcome.
        db.execute("INSERT INTO deliveries VALUES (?,?,?,?,?,?,?,NULL)",
                   (identifier, origin, room, did, str(nonce), text, "unknown"))
        db.commit()
        status, body = request()
        record, verified = verify(body)
        db.execute("UPDATE deliveries SET state=?,record=? WHERE id=?",
                   ("confirmed" if verified else "legacy", json.dumps(record), identifier))
        db.commit()
    print("Delivery ID: " + identifier)
    return status, record, verified


def command_reconcile(args):
    from agent import validate_base_url, validate_room, verify_export_file, parse_export_record
    from agent import verify_export_record, MAX_EXPORT_LINE_BYTES
    origin = validate_base_url(args.base_url)
    room = validate_room(args.room)
    verify_export_file(args.export_file, room)
    resolved = 0
    with journal(args.key_file) as db:
        pending = db.execute("SELECT id,did,nonce,text FROM deliveries "
                             "WHERE origin=? AND room=? AND state='unknown'", (origin, room)).fetchall()
        # Re-parse and re-verify every matched record; absence is never proof of failure.
        fd = os.open(str(args.export_file), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ValueError('export must remain a regular file')
        with os.fdopen(fd, "rb") as handle:
            while True:
                line = handle.readline(MAX_EXPORT_LINE_BYTES + 1)
                if not line:
                    break
                if len(line) > MAX_EXPORT_LINE_BYTES or not line.endswith(b"\n"):
                    raise ValueError("export changed or is incomplete")
                record = parse_export_record(line)
                if verify_export_record(room, record) != "verified":
                    continue
                for identifier, did, nonce, text in pending:
                    if (record.get("from"), str(record.get("nonce")), record.get("text")) == (did, nonce, text):
                        cursor = db.execute("UPDATE deliveries SET state='confirmed',record=? "
                                            "WHERE id=? AND state='unknown'", (json.dumps(record), identifier))
                        resolved += cursor.rowcount
        db.commit()
    print("Confirmed deliveries: {}. Unmatched requests remain unknown.".format(resolved))


def command_receipt(args):
    from agent import strict_json_loads, verify_export_record
    with journal(args.key_file) as db:
        row = db.execute("SELECT origin,room,state,record FROM deliveries WHERE id=?",
                         (args.delivery_id,)).fetchone()
    if not row or row[2] != "confirmed":
        raise ValueError("no confirmed signed receipt for this delivery")
    origin, room, _, raw = row
    record = strict_json_loads(raw)
    if verify_export_record(room, record) != "verified":
        raise ValueError("stored receipt signature is not verifiable")
    print(json.dumps({"schema": "technocore-signed-receipt/v1", "origin": origin,
                      "room": room, "record": record,
                      "scope": "Signature covers room, nonce and text; seq and ts are server assertions."},
                     ensure_ascii=False, indent=2))


def command_outbox(args):
    with journal(args.key_file) as db:
        rows = db.execute('SELECT id,state FROM deliveries ORDER BY rowid').fetchall()
    print(json.dumps([{'delivery_id': identifier, 'state': state} for identifier, state in rows]))
