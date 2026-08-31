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
import sys
import time
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
TIMESTAMP_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z"
)
SIGNED_URL_RE = re.compile(
    r"(?:https?://[^\s]+)?/(?:r/[^/\s]+/say-signed|"
    r"kv/[^/\s]+/[^/\s]+/set-signed)/\S+"
)


class HTTPStatusError(Exception):
    def __init__(self, status, body):
        self.status = status
        self.body = safe_error_excerpt(body)
        super().__init__(status, self.body)

    def __str__(self):
        detail = self.body or "empty response body"
        return "server rejected request (HTTP {}): {}".format(self.status, detail)


def b58encode(value):
    number = int.from_bytes(value, "big")
    encoded = []
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(B58[remainder])
    zeros = len(value) - len(value.lstrip(b"\x00"))
    return "1" * zeros + "".join(reversed(encoded))


def did_from_public_key(public_key):
    raw_public = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return "did:key:z" + b58encode(b"\xed\x01" + raw_public)


def generate_identity(key_file):
    key_file = Path(key_file)
    if key_file.exists():
        raise FileExistsError("identity already exists: {}".format(key_file))
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
    temporary = key_file.with_name(key_file.name + ".tmp")
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(key_file))
    except Exception:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise
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
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            descriptor = None
            payload = json.load(handle)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    raw_private = bytes.fromhex(payload["private_key_hex"])
    if len(raw_private) != 32:
        raise ValueError("invalid Ed25519 private key length")
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
    if record["seq"] < 1 or not isinstance(timestamp, str):
        raise ValueError("posted record is missing a valid sequence or timestamp")
    if not TIMESTAMP_RE.fullmatch(timestamp):
        raise ValueError("posted record timestamp is not canonical UTC RFC 3339")
    try:
        datetime.datetime.fromisoformat(timestamp[:-1] + "+00:00")
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
        raw_signature = base64.b64decode(
            stored_signature + "==", altchars=b"-_", validate=True
        )
    except (ValueError, binascii.Error) as error:
        raise ValueError("posted record signature is not canonical base64url") from error
    canonical = base64.urlsafe_b64encode(raw_signature).decode("ascii").rstrip("=")
    if len(raw_signature) != 64 or canonical != stored_signature:
        raise ValueError("posted record signature is not canonical base64url")
    signed = "{}|{}|{}".format(room, nonce, text).encode("utf-8")
    try:
        public_key.verify(raw_signature, signed)
    except InvalidSignature as error:
        raise ValueError("posted record signature does not verify") from error
    return record, True


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
            return response.status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as error:
        body = error.read(MAX_ERROR_RESPONSE_BYTES).decode("utf-8", errors="replace")
        raise HTTPStatusError(error.code, body) from None


def command_init(args):
    _, did = generate_identity(args.key_file)
    print("Identity created: {}".format(args.key_file))
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
    if not args.commit:
        print("DRY RUN: signed locally; no message was broadcast")
        print("DID: {}".format(did))
        print("Room: {}".format(room))
        print("Message: {}".format(text))
        if args.show_url:
            print("One-time signed URL: {}".format(url))
        return
    status, body = request_text(url + "?format=json", args.timeout)
    record, reverified = verify_posted_record(
        private_key.public_key(), room, did, nonce, text, signature, json.loads(body)
    )
    print("Signed message broadcast (HTTP {})".format(status))
    print("Stored sequence: {}".format(record["seq"]))
    print("Stored timestamp: {}".format(record["ts"]))
    if reverified:
        print("Stored signature: verified locally")
    else:
        print("Stored signature: unavailable on this server version")
    print("View: {}/humans#r/{}".format(validate_base_url(args.base_url), room))


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
        "--show-url", action="store_true", help="print the one-time signed URL in dry-run"
    )
    send_parser.set_defaults(func=command_send)
    return result


def main():
    args = parser().parse_args()
    try:
        args.func(args)
    except (OSError, ValueError, KeyError, json.JSONDecodeError, HTTPStatusError) as error:
        print("error: {}".format(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
