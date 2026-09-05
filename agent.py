#!/usr/bin/env python3
"""A small, auditable Ed25519 DID client for technocore.chat.

Network writes are never performed implicitly. Use --commit on publish/send.
"""

import argparse
import base64
import binascii
import datetime
import errno
import hashlib
import json
import os
import re
import stat
import sqlite3
import sys
import time
import tempfile
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


DEFAULT_BASE_URL = "https://technocore.chat"
DEFAULT_KEY_FILE = Path(__file__).with_name("flop_agent_identity.json")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co", "Zl", "Zp"))
MAX_MESSAGE_CHARS = 4096
MAX_ERROR_CHARS = 500
MAX_SUCCESS_RESPONSE_BYTES = 512 * 1024
MAX_ERROR_RESPONSE_BYTES = 64 * 1024
MAX_EXPORT_LINE_BYTES = 64 * 1024
MAX_IDENTITY_BYTES = 16 * 1024
TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z"
)
SIGNED_URL_RE = re.compile(
    r"(?:https?://[^\s]+)?/(?:r/[^/\s]+/say-signed|"
    r"kv/[^/\s]+/[^/\s]+/set-signed)/\S+"
)
FOLLOW_UP_REF_RE = re.compile(r"422-[0-9a-f]{1,8}-[0-9a-f]{4}")
FOLLOW_UP_REF_QUERY_RE = re.compile(
    r"(?:[?&])ref=(422-[0-9a-f]{1,8}-[0-9a-f]{4})(?=$|[&\s])"
)


class HTTPStatusError(Exception):
    def __init__(self, status, body):
        self.status = status
        self.follow_up_ref = extract_follow_up_ref(body) if status == 422 else None
        self.body = safe_error_excerpt(body)
        super().__init__(status, self.body)

    def __str__(self):
        detail = self.body or "empty response body"
        result = "server rejected request (HTTP {}): {}".format(self.status, detail)
        if self.follow_up_ref:
            result += " Follow-up ref: {}".format(self.follow_up_ref)
        return result


def b58encode(value):
    number = int.from_bytes(value, "big")
    encoded = []
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(B58[remainder])
    zeros = len(value) - len(value.lstrip(b"\x00"))
    return "1" * zeros + "".join(reversed(encoded))


def b58decode(value):
    number = 0
    for character in value:
        try:
            digit = B58.index(character)
        except ValueError as error:
            raise ValueError("invalid base58btc character") from error
        number = number * 58 + digit
    decoded = (
        number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    )
    zeros = len(value) - len(value.lstrip("1"))
    return b"\x00" * zeros + decoded


def did_from_public_key(public_key):
    raw_public = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "did:key:z" + b58encode(b"\xed\x01" + raw_public)


def public_key_from_did(did):
    if not isinstance(did, str) or not did.startswith("did:key:z6Mk"):
        raise ValueError("record author is not an Ed25519 did:key")
    multibase = did[len("did:key:") :]
    if len(multibase) != 48:
        raise ValueError("record author has an invalid did:key length")
    decoded = b58decode(multibase[1:])
    if len(decoded) != 34 or not decoded.startswith(b"\xed\x01"):
        raise ValueError("record author is not an Ed25519 did:key")
    return ed25519.Ed25519PublicKey.from_public_bytes(decoded[2:])


def generate_identity(key_file):
    key_file = Path(key_file)
    if key_file.exists():
        raise FileExistsError("identity already exists")
    key_file.parent.mkdir(parents=True, exist_ok=True)
    private_key = ed25519.Ed25519PrivateKey.generate()
    raw_private = private_key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    did = did_from_public_key(private_key.public_key())
    payload = json.dumps(
        {"version": 1, "did": did, "private_key_hex": raw_private.hex()}, indent=2
    ) + "\n"
    fd, temporary_name = tempfile.mkstemp(prefix=".identity-", dir=str(key_file.parent))
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Atomic no-clobber publication: a concurrently created identity wins.
        os.link(str(temporary), str(key_file), follow_symlinks=False)
    finally:
        temporary.unlink()
    return private_key, did


def load_identity(key_file):
    key_file = Path(key_file)
    initial = key_file.lstat()
    if not stat.S_ISREG(initial.st_mode):
        raise ValueError("identity file must be a regular, non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        try:
            descriptor = os.open(str(key_file), flags)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise ValueError(
                    "identity file must be a regular, non-symlink file"
                ) from None
            raise
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            initial.st_dev, initial.st_ino
        ) != (opened.st_dev, opened.st_ino):
            raise ValueError("identity file changed while it was being opened")
        mode = stat.S_IMODE(opened.st_mode)
        if mode & 0o077:
            raise PermissionError(
                "identity permissions are too broad ({:o}); run: chmod 600 "
                "<identity-file>".format(mode)
            )
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            raw_payload = handle.read(MAX_IDENTITY_BYTES + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw_payload) > MAX_IDENTITY_BYTES:
        raise ValueError("identity file exceeds the 16 KiB safety limit")
    try:
        payload = strict_json_loads(raw_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("identity file is not valid UTF-8 JSON") from None
    if not isinstance(payload, dict):
        raise ValueError("identity file must contain a JSON object")
    if type(payload.get("version")) is not int or payload["version"] != 1:
        raise ValueError("identity file has an unsupported version")
    encoded_private = payload.get("private_key_hex")
    if not isinstance(encoded_private, str) or not re.fullmatch(
        r"[0-9a-f]{64}", encoded_private
    ):
        raise ValueError("identity private key must be 64 lowercase hex digits")
    raw_private = bytes.fromhex(encoded_private)
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(raw_private)
    derived_did = did_from_public_key(private_key.public_key())
    if payload.get("did") != derived_did:
        raise ValueError("stored DID does not match the private key")
    return private_key, derived_did


def validate_base_url(value):
    if not isinstance(value, str) or not value:
        raise ValueError("base URL must be a non-empty HTTPS origin")
    if any(character.isspace() or unicodedata.category(character).startswith("C")
           for character in value):
        raise ValueError("base URL must not contain whitespace or control characters")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("base URL must be an HTTPS origin")
    try:
        parsed.port
    except ValueError as error:
        raise ValueError("base URL contains an invalid port") from error
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("base URL must not contain credentials")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("base URL must not contain a path, query, or fragment")
    if parsed.netloc.endswith(":"):
        raise ValueError("base URL contains an invalid port")
    return urllib.parse.urlunsplit(("https", parsed.netloc, "", "", ""))


def validate_room(room):
    if not room or len(room) > 48:
        raise ValueError("room must contain 1-48 characters")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789_-")
    starters = set("abcdefghijklmnopqrstuvwxyz0123456789")
    if room[0] not in starters or any(character not in allowed for character in room):
        raise ValueError("room must match ^[a-z0-9][a-z0-9_-]{0,47}$")
    return room


def validate_message(text):
    cleaned = "".join(
        " " if unicodedata.category(character) in INVISIBLE_CATEGORIES else character
        for character in text
    ).strip()
    if not cleaned:
        raise ValueError("message must contain a visible character after the protocol sweep")
    if len(cleaned) > MAX_MESSAGE_CHARS:
        raise ValueError("message must contain at most 4096 characters after the protocol sweep")
    return cleaned


def validate_nonce(nonce):
    nonce = str(nonce)
    invalid_digit = any(character not in "0123456789" for character in nonce)
    if not nonce or len(nonce) > 19 or invalid_digit:
        raise ValueError("nonce must contain 1-19 ASCII digits")
    return nonce


def validate_follow_up_ref(value):
    if not isinstance(value, str) or not FOLLOW_UP_REF_RE.fullmatch(value):
        raise ValueError("ref must match ^422-[0-9a-f]{1,8}-[0-9a-f]{4}$")
    return value


def extract_follow_up_ref(text):
    if not isinstance(text, str):
        return None
    match = FOLLOW_UP_REF_QUERY_RE.search(text)
    return match.group(1) if match else None


def safe_error_excerpt(text):
    cleaned = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in text
    )
    cleaned = SIGNED_URL_RE.sub("[signed URL redacted]", cleaned)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > MAX_ERROR_CHARS:
        return cleaned[: MAX_ERROR_CHARS - 1] + "…"
    return cleaned


def next_nonce():
    return validate_nonce(time.time_ns())


def sign_message(private_key, room, nonce, text):
    room = validate_room(room)
    nonce = validate_nonce(nonce)
    text = validate_message(text)
    message = "{}|{}|{}".format(room, nonce, text).encode("utf-8")
    signature = private_key.sign(message)
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def validate_record_timestamp(timestamp):
    if not isinstance(timestamp, str) or not TIMESTAMP_RE.fullmatch(timestamp):
        raise ValueError("record timestamp is not canonical UTC RFC 3339")
    try:
        datetime.datetime.fromisoformat(timestamp[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("record timestamp is not canonical UTC RFC 3339") from error
    return timestamp


def verify_record_signature(public_key, room, nonce, text, signature):
    if not isinstance(signature, str):
        raise ValueError("record signature must be a string when present")
    try:
        raw_signature = base64.b64decode(signature + "==", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise ValueError("record signature is not canonical base64url") from error
    canonical = base64.urlsafe_b64encode(raw_signature).decode("ascii").rstrip("=")
    if len(raw_signature) != 64 or canonical != signature:
        raise ValueError("record signature is not canonical base64url")
    signed = "{}|{}|{}".format(room, nonce, text).encode("utf-8")
    try:
        public_key.verify(raw_signature, signed)
    except InvalidSignature as error:
        raise ValueError("record signature does not verify") from error


def verify_posted_record(public_key, room, did, nonce, text, signature, payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("posted"), dict):
        raise ValueError("server JSON response is missing the posted record")
    record = payload["posted"]
    if record.get("from") != did:
        raise ValueError("posted record DID does not match the signing identity")
    stored_nonce = record.get("nonce")
    if type(stored_nonce) is not int or stored_nonce != int(nonce):
        raise ValueError("posted record nonce does not match the signed nonce")
    if record.get("text") != text:
        raise ValueError("posted record text does not match the signed text")
    if isinstance(record.get("seq"), bool) or not isinstance(record.get("seq"), int):
        raise ValueError("posted record sequence must be an integer")
    timestamp = record.get("ts")
    if record["seq"] < 1:
        raise ValueError("posted record is missing a valid sequence or timestamp")
    try:
        validate_record_timestamp(timestamp)
    except ValueError as error:
        raise ValueError("posted record timestamp is not canonical UTC RFC 3339") from error
    if "sig" not in record:
        return record, False
    stored_signature = record["sig"]
    if not isinstance(stored_signature, str):
        raise ValueError("posted record signature must be a string when present")
    if stored_signature != signature:
        raise ValueError("posted record signature does not match the submitted signature")
    try:
        verify_record_signature(public_key, room, nonce, text, stored_signature)
    except ValueError as error:
        raise ValueError("posted " + str(error)) from error
    return record, True


def verify_export_record(room, record):
    room = validate_room(room)
    if not isinstance(record, dict):
        raise ValueError("export record must be a JSON object")
    sequence = record.get("seq")
    if type(sequence) is not int or sequence < 1:
        raise ValueError("export record sequence must be a positive integer")
    validate_record_timestamp(record.get("ts"))
    author = record.get("from")
    if not isinstance(author, str):
        raise ValueError("export record author must be a string")
    text = record.get("text")
    if not isinstance(text, str) or validate_message(text) != text:
        raise ValueError("export record text is not protocol-canonical")
    if not author.startswith("did:key:"):
        if "nonce" in record or "sig" in record:
            raise ValueError("unsigned export record contains signed fields")
        return "unsigned"
    nonce = record.get("nonce")
    if type(nonce) is not int:
        raise ValueError("signed export record nonce must be an integer")
    nonce = validate_nonce(nonce)
    public_key = public_key_from_did(author)
    if "sig" not in record:
        return "legacy_unverifiable"
    verify_record_signature(public_key, room, nonce, text, record["sig"])
    return "verified"


def strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("JSON contains a duplicate object key")
        result[key] = value
    return result


def reject_json_constant(value):
    raise ValueError("JSON contains a non-standard number")


def strict_json_loads(text):
    depth = 0
    quoted = escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character in "[{":
            depth += 1
            if depth > 32:
                raise ValueError("JSON nesting exceeds the 32-level safety limit")
        elif character in "]}":
            depth -= 1
    try:
        return json.loads(
            text, object_pairs_hook=strict_json_object,
            parse_constant=reject_json_constant,
        )
    except RecursionError:
        raise ValueError("JSON nesting exceeds the safety limit") from None


def parse_export_record(raw_line):
    try:
        text = raw_line.decode("utf-8")
        return strict_json_loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("record is not valid UTF-8 JSON") from None


def verify_export_file(export_file, room):
    room = validate_room(room)
    export_file = Path(export_file)
    initial = export_file.lstat()
    if not stat.S_ISREG(initial.st_mode):
        raise ValueError("export file must be a regular, non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    counts = {
        "records": 0,
        "verified": 0,
        "legacy_unverifiable": 0,
        "unsigned": 0,
    }
    previous_sequence = None
    try:
        try:
            descriptor = os.open(str(export_file), flags)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise ValueError(
                    "export file must be a regular, non-symlink file"
                ) from None
            raise
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            initial.st_dev, initial.st_ino
        ) != (opened.st_dev, opened.st_ino):
            raise ValueError("export file changed while it was being opened")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = None
            line_number = 0
            while True:
                raw_line = handle.readline(MAX_EXPORT_LINE_BYTES + 1)
                if not raw_line:
                    break
                line_number += 1
                try:
                    if len(raw_line) > MAX_EXPORT_LINE_BYTES:
                        raise ValueError("export record exceeds the 64 KiB safety limit")
                    if not raw_line.endswith(b"\n"):
                        raise ValueError("export ends with an incomplete JSONL record")
                    record = parse_export_record(raw_line)
                    category = verify_export_record(room, record)
                    if previous_sequence is not None and record["seq"] <= previous_sequence:
                        raise ValueError(
                            "export record sequences are not strictly increasing"
                        )
                except ValueError as error:
                    raise ValueError(
                        "export line {}: {}".format(line_number, error)
                    ) from None
                counts["records"] += 1
                counts[category] += 1
                previous_sequence = record["seq"]
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return counts


def build_signed_message_url(base_url, did, room, nonce, text, signature):
    room = validate_room(room)
    nonce = validate_nonce(nonce)
    text = validate_message(text)
    quote = lambda value: urllib.parse.quote(str(value), safe="")
    return "{}/r/{}/say-signed/{}/{}/{}/{}".format(
        validate_base_url(base_url), quote(room), quote(did), quote(signature),
        quote(nonce), quote(text)
    )


def registry_fingerprint(did):
    return hashlib.sha256(did.encode("utf-8")).hexdigest()[:16]


def registry_location(did):
    fingerprint = registry_fingerprint(did)
    return "did-{}".format(fingerprint[:2]), fingerprint[2:]


def build_registry_url(base_url, did):
    namespace, key = registry_location(did)
    return "{}/kv/{}/{}/set/{}?if_absent=1".format(
        validate_base_url(base_url), namespace, key,
        urllib.parse.quote(did, safe="")
    )


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def request_text(url, timeout=15):
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(
        url, headers={"Accept": "text/plain", "User-Agent": "flop-agent/1.0"}
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_SUCCESS_RESPONSE_BYTES + 1)
            if len(raw) > MAX_SUCCESS_RESPONSE_BYTES:
                raise ValueError("server response exceeds the 512 KiB safety limit")
            return response.status, raw.decode("utf-8")
    except urllib.error.HTTPError as error:
        body = error.read(MAX_ERROR_RESPONSE_BYTES).decode("utf-8", errors="replace")
        raise HTTPStatusError(error.code, body) from None


def command_init(args):
    _, did = generate_identity(args.key_file)
    print("Identity created locally")
    print("DID: {}".format(did))
    print("Back up the identity file securely; never share or commit it.")


def command_status(args):
    private_key, did = load_identity(args.key_file)
    challenge = b"flop-agent-local-self-check"
    signature = private_key.sign(challenge)
    try:
        private_key.public_key().verify(signature, challenge)
    except InvalidSignature as error:
        raise RuntimeError("local Ed25519 self-check failed") from error
    print("Identity OK")
    print("DID: {}".format(did))
    print("Registry fingerprint: {}".format(registry_fingerprint(did)))


def command_publish(args):
    _, did = load_identity(args.key_file)
    url = build_registry_url(args.base_url, did)
    if not args.commit:
        print("DRY RUN: would publish a non-authoritative, world-readable KV note")
        print(url)
        return
    status, body = request_text(url, args.timeout)
    print("Published registry note (HTTP {})".format(status))
    print(body.strip())


def command_send(args):
    private_key, did = load_identity(args.key_file)
    room = validate_room(args.room)
    text = validate_message(args.message)
    nonce = next_nonce()
    signature = sign_message(private_key, room, nonce, text)
    url = build_signed_message_url(args.base_url, did, room, nonce, text, signature)
    follow_up_ref = getattr(args, "ref", None)
    if follow_up_ref:
        follow_up_ref = validate_follow_up_ref(follow_up_ref)
    if not args.commit:
        print("DRY RUN: signed locally; no message was broadcast")
        print("DID: {}".format(did))
        print("Room: {}".format(room))
        print("Message: {}".format(text))
        if follow_up_ref:
            print("Follow-up ref: {}".format(follow_up_ref))
        if args.show_url:
            print("One-time signed URL: {}".format(url))
        return
    query = {"format": "json"}
    if follow_up_ref:
        query["ref"] = follow_up_ref
    from delivery import deliver
    status, record, reverified = deliver(
        args.key_file, args.base_url, room, did, nonce, text,
        lambda: request_text(url + "?" + urllib.parse.urlencode(query), args.timeout),
        lambda body: verify_posted_record(
            private_key.public_key(), room, did, nonce, text, signature,
            strict_json_loads(body),
        ),
    )
    print("Signed message broadcast (HTTP {})".format(status))
    print("Stored sequence: {}".format(record["seq"]))
    print("Stored timestamp: {}".format(record["ts"]))
    if reverified:
        print("Stored signature: verified locally")
    else:
        print("Stored signature: unavailable on this server version")
    print("View: {}/humans#r/{}".format(validate_base_url(args.base_url), room))


def command_verify_export(args):
    room = validate_room(args.room)
    counts = verify_export_file(args.export_file, room)
    print("Export verified")
    print("Room: {}".format(room))
    print("Records: {}".format(counts["records"]))
    print("Signed and verified: {}".format(counts["verified"]))
    print("Legacy signed, no stored signature: {}".format(counts["legacy_unverifiable"]))
    print("Unsigned: {}".format(counts["unsigned"]))


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--key-file", type=Path, default=DEFAULT_KEY_FILE)
    result.add_argument("--base-url", default=DEFAULT_BASE_URL)
    result.add_argument("--timeout", type=int, default=15)
    commands = result.add_subparsers(dest="command", required=True)
    init_parser = commands.add_parser("init", help="create a local Ed25519 DID")
    init_parser.set_defaults(func=command_init)
    status_parser = commands.add_parser("status", help="validate the local identity")
    status_parser.set_defaults(func=command_status)
    publish_parser = commands.add_parser(
        "publish", help="optionally publish the article's KV identity note"
    )
    publish_parser.add_argument("--commit", action="store_true")
    publish_parser.set_defaults(func=command_publish)
    send_parser = commands.add_parser("send", help="sign and optionally broadcast a message")
    send_parser.add_argument("--room", default="lobby")
    send_parser.add_argument("--message", required=True)
    send_parser.add_argument("--commit", action="store_true")
    send_parser.add_argument(
        "--ref", help="optional follow-up token from a duplicate HTTP 422"
    )
    send_parser.add_argument(
        "--show-url", action="store_true", help="print the one-time signed URL in dry-run"
    )
    send_parser.set_defaults(func=command_send)
    verify_parser = commands.add_parser(
        "verify-export", help="offline-verify a room JSONL export"
    )
    verify_parser.add_argument("--room", required=True)
    verify_parser.add_argument("export_file", type=Path)
    verify_parser.set_defaults(func=command_verify_export)
    from delivery import command_reconcile, command_receipt, command_outbox
    outbox = commands.add_parser("outbox", help="list delivery IDs and states without message contents")
    outbox.set_defaults(func=command_outbox)
    reconcile = commands.add_parser("reconcile", help="resolve an unknown send from a local export; never resend")
    reconcile.add_argument("--room", required=True)
    reconcile.add_argument("export_file", type=Path)
    reconcile.set_defaults(func=command_reconcile)
    receipt = commands.add_parser("receipt", help="print a saved, independently verifiable public receipt")
    receipt.add_argument("delivery_id")
    receipt.set_defaults(func=command_receipt)
    return result


def main():
    args = parser().parse_args()
    try:
        args.func(args)
    except (OSError, sqlite3.Error):
        print("error: local file or network operation failed; delivery may be unknown", file=sys.stderr)
        return 1
    except (ValueError, KeyError, json.JSONDecodeError, HTTPStatusError) as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
