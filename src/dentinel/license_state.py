"""Versioned, bounded local-state recipe for compatible Sentinel SEA sources.

This changes application-local state, not the vendor's signatures or any global
cryptographic primitive. Incompatible input must be inspected before support is
added; unknown versions are never patched by blindly searching fixed offsets.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import re
from dataclasses import dataclass
from pathlib import Path

from .common import CHUNK
from .sea import SeaSource, read_source

MODE = "enterprise-state"
RECIPE = "dentinel-enterprise-state-v1"
MARKER = b"/*DENTINEL_ENTERPRISE_STATE_V1*/"
IDENTIFIER = rb"[A-Za-z_$][A-Za-z0-9_$]*"
FEATURES = {name: True for name in (
    "accessLogs", "clickhouse", "eml", "externalRedis", "ldap", "mariadb",
    "mssql", "mysql", "oauth", "oracledb", "otel", "postgres", "rbac",
)}
FEATURES["trial"] = False
LIMITS = {"accounts": -1, "instances": -1, "throttle": 0, "users": -1}


@dataclass(frozen=True)
class Token:
    value: bytes
    start: int
    end: int


def _quoted(code: bytes, at: int, end: int) -> int:
    quote, cursor = code[at], at + 1
    while cursor < end:
        value = code[cursor]
        if value == 92:
            cursor += 2
        elif value == quote:
            return cursor + 1
        elif value in (10, 13):
            raise ValueError("Unsupported unterminated JS string")
        else:
            cursor += 1
    raise ValueError("Unterminated JS string")


def _regex(code: bytes, at: int, end: int) -> int:
    cursor, char_class = at + 1, False
    while cursor < end:
        value = code[cursor]
        if value == 92:
            cursor += 2
            continue
        if value in (10, 13):
            raise ValueError("Unterminated JS regular expression")
        if value == 91:
            char_class = True
        elif value == 93:
            char_class = False
        elif value == 47 and not char_class:
            cursor += 1
            while cursor < end and (65 <= code[cursor] <= 90 or 97 <= code[cursor] <= 122):
                cursor += 1
            return cursor
        cursor += 1
    raise ValueError("Unterminated JS regular expression")


def _template(code: bytes, at: int, end: int, nesting: int) -> int:
    if nesting > 32:
        raise ValueError("JS template nesting exceeds supported depth")
    cursor = at + 1
    while cursor < end:
        if code[cursor] == 92:
            cursor += 2
        elif code[cursor] == 96:
            return cursor + 1
        elif code[cursor:cursor + 2] == b"${":
            cursor = matching(code, cursor + 1, end=end, nesting=nesting + 1)
        else:
            cursor += 1
    raise ValueError("Unterminated JS template")


def tokens(code: bytes, start: int, end: int, *, nesting: int = 0):
    """Lex only the bounded target class; not a general JavaScript parser."""
    cursor, previous, before_previous = start, b"", b""
    control_parens: list[bool] = []
    control_words = {b"if", b"while", b"for", b"with", b"switch", b"catch"}
    regex_before = {b"", b"(", b"[", b"{", b",", b"=", b":", b";", b"return", b"throw", b"!", b"&&", b"||", b"?", b"=>", b"case", b"in", b"of", b"instanceof", b"void", b"typeof", b"delete", b"yield", b"await", b"else", b"do", b"<control-close>"}
    while cursor < end:
        value = code[cursor]
        if value in b" \t\r\n\f\v":
            cursor += 1
            continue
        if code[cursor:cursor + 2] == b"//":
            following = code.find(b"\n", cursor + 2, end)
            cursor = end if following < 0 else following + 1
            continue
        if code[cursor:cursor + 2] == b"/*":
            following = code.find(b"*/", cursor + 2, end)
            if following < 0:
                raise ValueError("Unterminated JS comment")
            cursor = following + 2
            continue
        at = cursor
        if value in (34, 39):
            cursor = _quoted(code, cursor, end)
            text = b"<literal>"
        elif value == 96:
            cursor = _template(code, cursor, end, nesting)
            text = b"<literal>"
        elif value == 47 and previous == b"}":
            raise ValueError("Ambiguous JS slash after closing brace is unsupported")
        elif value == 47 and previous in regex_before:
            cursor = _regex(code, cursor, end)
            text = b"<literal>"
        elif 65 <= value <= 90 or 97 <= value <= 122 or value in (95, 36):
            cursor += 1
            while cursor < end and (code[cursor:cursor + 1].isalnum() or code[cursor] in (95, 36)):
                cursor += 1
            text = code[at:cursor]
        elif 48 <= value <= 57:
            cursor += 1
            while cursor < end and (code[cursor:cursor + 1].isalnum() or code[cursor] in (46, 95)):
                cursor += 1
            text = b"<number>"
        elif value < 128:
            text = code[cursor:cursor + 2] if code[cursor:cursor + 2] in (b"=>", b"&&", b"||", b"?.", b"??", b"++", b"--", b"==", b"!=", b"<=", b">=") else code[cursor:cursor + 1]
            cursor += len(text)
        else:
            raise ValueError("Unsupported non-ASCII JS token in license class")
        next_previous = text
        if text == b"(":
            control_parens.append(previous in control_words and before_previous not in (b".", b"?."))
        elif text == b")" and control_parens:
            if control_parens.pop():
                next_previous = b"<control-close>"
        yield Token(text, at, cursor)
        before_previous, previous = previous, next_previous


def matching(code: bytes, start: int, *, end: int | None = None, nesting: int = 0) -> int:
    end = len(code) if end is None else end
    opening = code[start:start + 1]
    pairs = {b"{": b"}", b"[": b"]", b"(": b")"}
    if opening not in pairs:
        raise ValueError("Expected a JS opening delimiter")
    stack: list[bytes] = []
    for token in tokens(code, start, end, nesting=nesting):
        if token.value in pairs:
            stack.append(pairs[token.value])
        elif token.value in (b"}", b"]", b")"):
            if not stack or stack.pop() != token.value:
                raise ValueError("Unbalanced JS delimiters")
            if not stack:
                return token.end
    raise ValueError("Unclosed or oversized JS license class")


@dataclass(frozen=True)
class StatePatch:
    sea: SeaSource
    class_name: str
    instance_name: str
    status_name: str
    class_start: int
    class_end: int
    body_start: int
    body_end: int
    original: bytes
    replacement: bytes
    discovered_features: tuple[str, ...]
    discovered_limits: tuple[str, ...]

    @property
    def offset(self) -> int:
        return self.sea.source_offset + self.body_start

    def details(self) -> dict:
        return {
            "recipe": RECIPE, "match_count": 1,
            "sea": {"main_path": self.sea.code_path, "source_offset": self.sea.source_offset,
                    "source_size": self.sea.source_size, "flags": self.sea.flags,
                    "snapshot": False, "code_cache": False},
            "class_identifier": self.class_name, "instance_identifier": self.instance_name,
            "status_identifier": self.status_name,
            "changes": [{"offset": self.offset, "length": len(self.original),
                         "before_sha256": hashlib.sha256(self.original).hexdigest(),
                         "after_sha256": hashlib.sha256(self.replacement).hexdigest()}],
            "discovered_features": list(self.discovered_features),
            "discovered_limits": list(self.discovered_limits),
            "local_state": {"id": "dentinel-local", "plan": "enterprise", "support": "enterprise",
                            "features": FEATURES.copy(), "limits": LIMITS.copy(),
                            "trial": False, "vendor_signed": False},
            "background_license_refresh": False, "license_network_disabled": True,
            "vendor_crypto_unchanged": True, "file_size_preserved": True,
        }


def _body(status_name: str) -> bytes:
    features = json.dumps(FEATURES, sort_keys=True, separators=(",", ":"))
    limits = json.dumps(LIMITS, sort_keys=True, separators=(",", ":"))
    # Object descriptors shadow existing public fields/prototype methods. The
    # backing envelope is deeply frozen, and later assignments are ignored.
    # Keep the original signature verifier/validator unchanged; this local
    # envelope explicitly has no vendor signature and is never written to cache.
    text = (
        MARKER.decode() + "if(this.loadTimeout)clearTimeout(this.loadTimeout);this.loadTimeout=null;"
        'if(!Object.prototype.hasOwnProperty.call(this,"__dentinelState")){'
        f'const f=Object.freeze({features}),l=Object.freeze({limits}),'
        'v=Object.freeze({id:"dentinel-local",plan:"enterprise",support:"enterprise",'
        'validFrom:0,validUntil:null,verifiedAt:0,features:f,limits:l}),'
        'd=Object.freeze({license:v,publicKey:"",signature:"",source:"dentinel-local-override"});'
        'Object.defineProperty(this,"__dentinelState",{value:d});'
        'Object.defineProperties(this,{data:{get:()=>d,set:()=>{}},'
        'licenseId:{get:()=>v.id,set:()=>{}},loadIntervalSec:{get:()=>0,set:()=>{}},'
        'hello:{value:async()=>d},check:{value:async()=>({valid:true,local:true})},'
        'writeLicense:{value:async()=>{}}});}'
        + status_name + '=0;return this.data;'
    )
    return text.encode("ascii")


def locate(sea: SeaSource) -> StatePatch:
    code = sea.code
    if MARKER in code or b"__dentinelState" in code:
        raise ValueError("Binary is already enterprise-state patched")
    getter = re.compile(rb"get\s+features\s*\(\s*\)\s*\{\s*return\s+this\.data\?\.license\?\.features\s*\|\|\s*null\s*;?\s*\}")
    hits = list(getter.finditer(code))
    if len(hits) != 1:
        raise ValueError("Expected one compatible license features getter")
    anchor = hits[0].start()
    definitions = list(re.finditer(rb"(?<![\w$.])(" + IDENTIFIER + rb")\s*=\s*class\s*\{", code[max(0, anchor - 65536):anchor]))
    if not definitions:
        raise ValueError("Compatible license class declaration not found")
    declaration = definitions[-1]
    class_start = max(0, anchor - 65536) + declaration.start()
    class_name = declaration.group(1).decode("ascii")
    class_open = max(0, anchor - 65536) + declaration.end() - 1
    class_end = matching(code, class_open, end=min(len(code), class_open + 65536))
    if class_end <= hits[0].end():
        raise ValueError("Features getter is not inside the selected license class")
    class_code = code[class_open:class_end]
    for feature in (b"KNOWN_PUBLIC_KEYS", b"LICENSE_SERVER", b"loadTimeout", b"loadIntervalSec", b"verifySignature", b"writeLicense"):
        if feature not in class_code:
            raise ValueError(f"Unsupported license class: missing {feature.decode()}")
    for prop in (b"limits", b"plan"):
        if not re.search(rb"get\s+" + prop + rb"\s*\(\s*\)\s*\{\s*return\s+this\.data\?\.license\?\." + prop + rb"\s*\|\|\s*null\s*;?\s*\}", class_code):
            raise ValueError("Unsupported license state getter contract")
    depth = 0
    method_positions = set()
    for token in tokens(code, class_open, class_end):
        if depth == 1 and token.value == b"async":
            method_positions.add(token.start)
        if token.value == b"{":
            depth += 1
        elif token.value == b"}":
            depth -= 1
    methods = [m for m in re.finditer(rb"async\s+load\s*\(\s*(?P<parameter>" + IDENTIFIER + rb")?\s*\)\s*\{", code[class_open:class_end]) if class_open + m.start() in method_positions]
    if len(methods) != 1:
        raise ValueError("Expected exactly one top-level async load method")
    method = methods[0]
    body_open = class_open + method.end() - 1
    body_close = matching(code, body_open, end=class_end) - 1
    body_start, body_end = body_open + 1, body_close
    old = code[body_start:body_end]
    for feature in (b"this.verifySignature", b"this.hello", b"this.loadTimeout", b"this.loadIntervalSec", b"this.data"):
        if feature not in old:
            raise ValueError("Unrecognized license loader semantics")
    prefix = code[max(0, class_start - 4096):class_start]
    states = []
    for match in re.finditer(rb"function\s+(" + IDENTIFIER + rb")\s*\(\s*\)\s*\{\s*(" + IDENTIFIER + rb")\s*=\s*0\s*;?\s*\}", prefix):
        state = match.group(2)
        if (re.search(rb"\b(?:var|let|const)\s+" + re.escape(state) + rb"\s*=\s*0\b", prefix)
                and re.search(rb"return\s+" + re.escape(state) + rb"\s*;?\s*\}", prefix)
                and b"x-unlicensed" in prefix
                and re.search(rb"(?<![\w$])" + re.escape(state) + rb"\s*===\s*2\b", prefix)):
            states.append(state.decode("ascii"))
    if len(set(states)) != 1:
        raise ValueError("Unlicensed-state reset cannot be identified uniquely")
    status_name = states[0]
    if method.group("parameter") in {status_name.encode(), b"Object", b"clearTimeout"}:
        raise ValueError("License loader parameter shadows a local-state recipe dependency")
    instances = list(re.finditer(rb"(?<![\w$])(" + IDENTIFIER + rb")\s*=\s*new\s+" + re.escape(class_name.encode()) + rb"(?![\w$])(?:\s*\(\s*\))?\s*[;,]", code[class_end:class_end + 4096]))
    if len(instances) != 1:
        raise ValueError("Expected one license instance binding")
    instance = instances[0].group(1)
    access = rb"\s*(?:\?\.|\.)\s*"
    root = rb"(?<![\w$])" + re.escape(instance) + access
    license_path = rb"data" + access + rb"license" + access
    feature_prefix = root + rb"(?:" + license_path + rb")?features" + access
    limit_prefix = root + rb"(?:" + license_path + rb")?limits" + access
    features = {m.group(1).decode() for m in re.finditer(feature_prefix + rb"(" + IDENTIFIER + rb")", code)}
    limits = {m.group(1).decode() for m in re.finditer(limit_prefix + rb"(" + IDENTIFIER + rb")", code)}
    if not features or not limits or features - FEATURES.keys() or limits - LIMITS.keys():
        raise ValueError(f"Unknown license feature/limit contract: features={sorted(features)}, limits={sorted(limits)}")
    computed_path = root + rb"(?:features|limits|data(?:" + access + rb"license(?:" + access + rb"(?:features|limits))?)?)"
    if re.search(computed_path + rb"\s*(?:\?\.)?\s*\[", code):
        raise ValueError("Computed license feature/limit access is unsupported")
    replacement = _body(status_name)
    if len(replacement) > len(old):
        raise ValueError(f"Local-state recipe needs {len(replacement)} bytes but loader has {len(old)}")
    replacement = replacement.ljust(len(old), b" ")
    return StatePatch(sea, class_name, instance.decode(), status_name, class_start, class_end,
                      body_start, body_end, old, replacement, tuple(sorted(features)), tuple(sorted(limits)))


def plan(source: Path) -> StatePatch:
    with source.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        return locate(read_source(data))


def expected_sha256(source: Path, patch: StatePatch) -> str:
    digest = hashlib.sha256()
    with source.open("rb") as stream:
        remaining = patch.offset
        while remaining:
            block = stream.read(min(CHUNK, remaining))
            if not block:
                raise ValueError("Original changed while computing patch")
            digest.update(block)
            remaining -= len(block)
        if stream.read(len(patch.original)) != patch.original:
            raise ValueError("Patch preimage bytes changed")
        digest.update(patch.replacement)
        for block in iter(lambda: stream.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()
