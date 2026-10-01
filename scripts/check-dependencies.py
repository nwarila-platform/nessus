#!/usr/bin/env python3
"""Validate the credential-free dependency declaration contract.

Adapted from nwarila-platform/secure-wazuh's validator, which introduced the dependencies/ layout.
Two closures are added here: the playbook's pins must equal the declared artifacts, and the
runner's S3 policy must authorize exactly the declared objects under this repository's prefix.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT = REPO_ROOT / "dependencies"
AWS = ROOT / "aws"
PLAYBOOK = REPO_ROOT / "ansible" / "playbooks" / "nessus-aws.yml"
ROLE_DEFAULTS = REPO_ROOT / "ansible" / "applications" / "nessus_scanner" / "defaults" / "main.yml"

TOKENS = (
    "<account-id>",
    "<owner-id>",
    "<repository-id>",
    "<region>",
    "<vpc-id>",
    "<subnet-id>",
    "<ebs-kms-key-id>",
    "<key-pair-name>",
)
# Absent from the proven live baseline; a document that starts using one must say so here.
ABSENT_TOKENS = (
    "<vpc-id>",
    "<subnet-id>",
    "<ebs-kms-key-id>",
    "<key-pair-name>",
)
# Concrete values that must only ever appear as tokens. The account id is deliberately NOT listed:
# naming it here would publish it. The bare 12-digit scan below catches it without naming it.
FORBIDDEN = (
    "230745524",
    "1348478864",
    "us-east-1",
    "nwarila-ec2-key",
)
FORBIDDEN_PATTERNS = (
    re.compile(r"\bvpc-[0-9a-f]{8,17}\b"),
    re.compile(r"\bsubnet-[0-9a-f]{8,17}\b"),
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Alphanumeric boundaries avoid false positives on 12-digit substrings inside SHA-256 digests.
BARE_ACCOUNT = re.compile(r"(?<![0-9A-Za-z])\d{12}(?![0-9A-Za-z])")
URI = re.compile(r"registry://[A-Za-z0-9._/-]+")
TOKEN = re.compile(r"<[a-z0-9-]+>")

PREFIX = "nwarila-platform_nessus"
RUNNER_POLICIES = [f"{PREFIX}_runner_{s}" for s in ("ebs", "ec2", "eni", "iam", "kms", "s3", "sg", "ssm")]
REAPER_POLICIES = [f"{PREFIX}_reaper_{s}" for s in ("ebs", "ec2", "eni", "iam", "s3", "sg")]
POLICY_NAMES = tuple(sorted([f"{PREFIX}_admin_s3", *RUNNER_POLICIES, *REAPER_POLICIES]))
ROLE_ATTACH = {
    f"{PREFIX}_admin": sorted([f"{PREFIX}_admin_s3", *RUNNER_POLICIES]),
    f"{PREFIX}_reaper": REAPER_POLICIES,
    f"{PREFIX}_runner": RUNNER_POLICIES,
}
ROLE_SESSION_SECONDS = {f"{PREFIX}_admin": 3600, f"{PREFIX}_reaper": 3600, f"{PREFIX}_runner": 7800}
POLICY_VERSIONS = {name: "v1" for name in POLICY_NAMES}
POLICY_VERSIONS[f"{PREFIX}_runner_ec2"] = "v2"
# v2 added ReadOnlyTheNessusDeploymentObjects, published from the tracked document on 2026-09-30.
POLICY_VERSIONS[f"{PREFIX}_runner_s3"] = "v2"
# v2 and v3 added snapshot grants for preserve_data; v4 withdrew them with the flag, republishing
# v1's baseline document (all 2026-09-30).
POLICY_VERSIONS[f"{PREFIX}_runner_ebs"] = "v4"
EXPORTED = "2026-09-30"
NOT_YET_APPLIED: list[str] = []

BUCKETS = {
    "registry://aws/s3/ansible": "<account-id>-ansible",
    "registry://aws/s3/apprepo": "<account-id>-apprepo",
}
RESOLVER = {
    "registry://aws/s3/ansible": {
        "value": "<account-id>-ansible",
        "evidence": f"dependencies/aws/policies/{PREFIX}_admin_s3.json",
    },
    "registry://aws/s3/apprepo": {
        "value": "<account-id>-apprepo",
        "evidence": f"dependencies/aws/policies/{PREFIX}_runner_s3.json",
    },
}
# The one statement this repository adds to the fleet baseline; it must name exactly the declared
# objects under the ansible bucket.
RUNNER_OBJECT_SID = "ReadOnlyTheNessusDeploymentObjects"
APPREPO_WILDCARD = "arn:aws:s3:::<account-id>-apprepo/*"


class ContractError(Exception):
    """A dependency contract assertion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"JSON parse failed for {rel(path)}: {error}") from error


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ContractError(f"YAML parse failed for {rel(path)}: {error}") from error


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label}: expected a mapping")
    return value


def require_keys(value: dict[str, Any], required: set[str], optional: set[str], label: str) -> None:
    actual = set(value)
    require(required <= actual, f"{label}: missing keys {sorted(required - actual)}")
    require(actual <= required | optional, f"{label}: unknown keys {sorted(actual - required - optional)}")


def require_string_list(value: Any, label: str) -> list[str]:
    require(isinstance(value, list), f"{label}: expected a list")
    require(all(isinstance(item, str) for item in value), f"{label}: every entry must be a string")
    require(value == sorted(set(value)), f"{label}: entries must be unique and lexical")
    return value


def manifest_bytes() -> bytes:
    rows = []
    paths = sorted(
        (path for path in ROOT.rglob("*") if path.is_file() and path.name != "MANIFEST.sha256"),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  ./{path.relative_to(ROOT).as_posix()}\n")
    return "".join(rows).encode()


def check_integrity() -> None:
    require(ROOT.is_dir(), "dependencies/: directory is missing")
    symlinks = [rel(path) for path in ROOT.rglob("*") if path.is_symlink()]
    require(not symlinks, f"symlink refusal: {symlinks}")
    checksum = subprocess.run(
        ["sha256sum", "-c", "MANIFEST.sha256"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    require(
        checksum.returncode == 0,
        "checksum verification failed for (cd dependencies && sha256sum -c MANIFEST.sha256): "
        + (checksum.stdout + checksum.stderr).strip(),
    )
    require(
        (ROOT / "MANIFEST.sha256").read_bytes() == manifest_bytes(),
        "MANIFEST.sha256 differs from deterministic regeneration",
    )


def check_literals_and_tokens() -> None:
    for path in sorted(path for path in ROOT.rglob("*") if path.is_file()):
        text = path.read_text(encoding="utf-8")
        for literal in FORBIDDEN:
            require(literal not in text, f"forbidden concrete literal {literal!r} in {rel(path)}")
        for pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(text)
            require(match is None, f"forbidden concrete identifier {match.group() if match else ''!r} in {rel(path)}")
        match = BARE_ACCOUNT.search(text)
        require(match is None, f"bare 12-digit run {match.group() if match else ''!r} in {rel(path)}")
    iam_paths = [*sorted((AWS / "policies").glob("*.json")), *sorted((AWS / "roles").glob("*.trust.json"))]
    corpus = "".join(path.read_text(encoding="utf-8") for path in iam_paths)
    observed = set(TOKEN.findall(corpus))
    unknown = observed - set(TOKENS)
    require(not unknown, f"IAM documents contain tokens outside the closed vocabulary: {sorted(unknown)}")
    expected = set(TOKENS) - set(ABSENT_TOKENS)
    require(
        observed == expected,
        "IAM token set differs from the live-baseline presence record: "
        f"missing={sorted(expected - observed)} unexpectedly_present={sorted(observed - expected)}",
    )


def check_canonical_json() -> None:
    for path in [*sorted((AWS / "policies").glob("*.json")), *sorted((AWS / "roles").glob("*.trust.json"))]:
        document = load_json(path)
        expected = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
        require(path.read_bytes() == expected, f"canonical JSON serializer mismatch: {rel(path)}")


def check_declarations() -> dict[str, dict[str, Any]]:
    require(not (AWS / "proposed").exists(), "aws/proposed/ must not exist in the desired-state tree")
    require(not (AWS / "profiles").exists(), "aws/profiles/ must not exist; shared profiles are external dependencies")
    policy_json = {path.stem: path for path in (AWS / "policies").glob("*.json")}
    require(not list((AWS / "policies").glob("*.yml")), "policy YAML sidecars are forbidden; metadata belongs in aws/manifest.json")
    require(set(policy_json) == set(POLICY_NAMES), "desired policy JSON set differs from the closed expected set")

    trust_json = {path.name.removesuffix(".trust.json"): path for path in (AWS / "roles").glob("*.trust.json")}
    role_yaml = {path.stem: path for path in (AWS / "roles").glob("*.yml")}
    require(set(trust_json) == set(role_yaml) == set(ROLE_ATTACH), "role trust/YAML pairing is not one-to-one")
    roles = {}
    for name in sorted(role_yaml):
        path = role_yaml[name]
        sidecar = require_mapping(load_yaml(path), rel(path))
        required = {"schema", "name", "session_seconds", "trust", "attach", "managed_attach", "path", "description", "managed_by"}
        require_keys(sidecar, required, set(), rel(path))
        require(sidecar["schema"] == "aws-role/v1", f"{name}: invalid role schema")
        require(sidecar["name"] == name, f"{name}: sidecar name must equal filename stem")
        require(sidecar["trust"] == f"{name}.trust.json", f"{name}: trust must name its paired JSON")
        require(sidecar["session_seconds"] == ROLE_SESSION_SECONDS[name], f"{name}: session_seconds differs from live")
        require(sidecar["path"] == "/" and sidecar["description"] is None, f"{name}: path/description differ from live")
        require(sidecar["managed_by"] == "consumer", f"{name}: managed_by must be consumer")
        attach = require_string_list(sidecar["attach"], f"{name}.attach")
        require(attach == ROLE_ATTACH[name], f"{name}: customer-managed attachments differ from live")
        require(require_string_list(sidecar["managed_attach"], f"{name}.managed_attach") == [], f"{name}: AWS-managed attachments differ from live")
        roles[name] = sidecar
    attached = {policy for attachments in ROLE_ATTACH.values() for policy in attachments}
    require(attached == set(policy_json), "orphan policy file: desired policy attachment closure is incomplete")
    return roles


def check_manifest(roles: dict[str, dict[str, Any]]) -> None:
    manifest = require_mapping(load_json(AWS / "manifest.json"), "aws/manifest.json")
    require(list(manifest) == ["exported", "roles", "policies", "divergence"], "manifest top-level key order/schema is invalid")
    require(manifest["exported"] == EXPORTED, "manifest exported date is not the verified export date")
    require(list(manifest["roles"]) == sorted(roles), "manifest roles must equal sidecars in lexical order")
    for name, sidecar in roles.items():
        expected = [{"name": policy, "version": POLICY_VERSIONS[policy]} for policy in sidecar["attach"]]
        require(manifest["roles"][name] == {"attached": expected, "inline": []}, f"manifest role mismatch: {name}")
    policies = require_mapping(manifest["policies"], "manifest.policies")
    require(list(policies) == sorted(POLICY_NAMES), "manifest policies must equal the policy files in lexical order")
    for name, metadata in policies.items():
        expected = {"path": "/", "description": None, "tags": {}, "managed_by": "consumer"}
        require(metadata == expected, f"manifest policy metadata differs from the closed expected table: {name}")
    divergence = require_mapping(manifest["divergence"], "manifest.divergence")
    require(set(divergence) == {"note", "not_yet_applied"}, "manifest.divergence exact schema violation")
    require(isinstance(divergence["note"], str) and divergence["note"], "manifest.divergence.note must be non-empty")
    pending = require_string_list(divergence["not_yet_applied"], "manifest.divergence.not_yet_applied")
    require(set(pending) <= set(POLICY_NAMES), "manifest.divergence.not_yet_applied names a policy without a real policy JSON")
    require(pending == NOT_YET_APPLIED, "manifest.divergence.not_yet_applied differs from the recorded pending set")


def check_artifacts() -> list[dict[str, Any]]:
    document = require_mapping(load_yaml(AWS / "artifacts.yml"), "aws/artifacts.yml")
    require(set(document) == {"schema", "artifacts", "secrets"}, "aws/artifacts.yml: unknown or missing top-level keys")
    require(document["schema"] == "aws-artifacts/v1", "aws/artifacts.yml: invalid schema")
    objects = []
    for item in document["artifacts"]:
        item = require_mapping(item, "aws/artifacts.yml artifact")
        require_keys(item, {"bucket", "key", "sha256", "access"}, set(), f"artifact {item.get('key')}")
        require(HEX64.fullmatch(str(item["sha256"])) is not None, f"artifact {item['key']}: sha256 must be lowercase 64-hex")
        require(item["access"] == "controller-fetch", f"artifact {item['key']}: access must be controller-fetch")
        objects.append(item)
    for item in document["secrets"]:
        item = require_mapping(item, "aws/artifacts.yml secret")
        require_keys(item, {"bucket", "key", "access"}, set(), f"secret {item.get('key')}")
        require(item["access"] == "controller-secret-lookup", f"secret {item['key']}: access must be controller-secret-lookup")
        objects.append(item)
    for item in objects:
        require(item["bucket"] in BUCKETS, f"{item['key']}: bucket must be a declared registry URI")
    keys = [item["key"] for item in objects]
    require(len(keys) == len(set(keys)), "aws/artifacts.yml declares an object twice")
    return objects


def check_playbook_pins(objects: list[dict[str, Any]]) -> None:
    """The playbook consumes exactly what artifacts.yml declares, at the digests it declares."""
    plays = load_yaml(PLAYBOOK)
    role_vars = None
    for play in plays:
        for role in play.get("roles", []) or []:
            if isinstance(role, dict) and role.get("role") == "nessus_scanner":
                role_vars = role["vars"]["nessus_scanner"]
    require(role_vars is not None, f"{rel(PLAYBOOK)}: no nessus_scanner role declaration found")
    defaults = load_yaml(ROLE_DEFAULTS)["nessus_scanner_defaults"]
    installer = role_vars["installer"]
    installer_key = defaults["installer"]["key"].replace("<version>", str(installer["version"]))
    certificate_key = str(role_vars["certificate"]["key"]).replace("{{ nessus_objects_prefix }}", "applications/nessus")
    by_key = {item["key"]: item for item in objects}
    require(installer_key in by_key, f"the playbook installs {installer_key!r}, which artifacts.yml does not declare")
    require(by_key[installer_key]["sha256"] == installer["sha256"], "installer sha256 differs between the playbook and artifacts.yml")
    require(by_key[installer_key]["bucket"] == "registry://aws/s3/apprepo", "the installer must come from the application repository")
    require(certificate_key in by_key, f"the playbook imports {certificate_key!r}, which artifacts.yml does not declare")
    require(by_key[certificate_key]["sha256"] == role_vars["certificate"]["sha256"], "certificate sha256 differs between the playbook and artifacts.yml")
    text = PLAYBOOK.read_text(encoding="utf-8")
    for item in objects:
        if "sha256" not in item:
            require(Path(item["key"]).name in text, f"secret {item['key']} is declared but the playbook never reads it")


def check_authorization(objects: list[dict[str, Any]]) -> None:
    """The runner may read every declared object and nothing else under this repository's prefix."""
    policy = load_json(AWS / "policies" / f"{PREFIX}_runner_s3.json")
    statements = policy["Statement"]
    resources: set[str] = set()
    for statement in statements:
        actions = statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]]
        if statement["Effect"] == "Allow" and "s3:GetObject" in actions:
            listed = statement["Resource"] if isinstance(statement["Resource"], list) else [statement["Resource"]]
            resources.update(listed)
    own = [s for s in statements if s.get("Sid") == RUNNER_OBJECT_SID]
    require(len(own) == 1, f"{PREFIX}_runner_s3 must carry exactly one {RUNNER_OBJECT_SID} statement")
    declared_ansible = set()
    for item in objects:
        arn = f"arn:aws:s3:::{BUCKETS[item['bucket']]}/{item['key']}"
        if item["bucket"] == "registry://aws/s3/apprepo":
            require(APPREPO_WILDCARD in resources or arn in resources, f"the runner cannot read {item['key']}")
        else:
            declared_ansible.add(arn)
            require(arn in resources, f"the runner cannot read {item['key']}; grant it in {RUNNER_OBJECT_SID}")
    granted = set(own[0]["Resource"] if isinstance(own[0]["Resource"], list) else [own[0]["Resource"]])
    require(granted == declared_ansible, f"{RUNNER_OBJECT_SID} must grant exactly the declared objects: extra={sorted(granted - declared_ansible)}")


def check_registry_closure() -> None:
    resolver = require_mapping(load_yaml(ROOT / "registry-values.yml"), "registry-values.yml")
    require(resolver == RESOLVER, "registry-values.yml must contain exactly the evidenced resolver entries")
    for uri, entry in resolver.items():
        require((REPO_ROOT / entry["evidence"]).is_file(), f"{uri}: evidence {entry['evidence']} does not exist")
        require(entry["value"] in (REPO_ROOT / entry["evidence"]).read_text(encoding="utf-8"), f"{uri}: evidence does not contain its value")
    used = set()
    for path in sorted(path for path in ROOT.rglob("*") if path.is_file()):
        if path.name in {"registry-values.yml", "README.md"}:
            continue
        used.update(URI.findall(path.read_text(encoding="utf-8")))
    require(used == set(resolver), f"registry URI closure mismatch: used_only={sorted(used - set(resolver))} resolver_only={sorted(set(resolver) - used)}")


def main() -> int:
    try:
        check_integrity()
        check_literals_and_tokens()
        check_canonical_json()
        roles = check_declarations()
        check_manifest(roles)
        objects = check_artifacts()
        check_playbook_pins(objects)
        check_authorization(objects)
        check_registry_closure()
    except ContractError as error:
        print(f"dependency check failed: {error}", file=sys.stderr)
        return 1
    print("dependency check passed: declarations, metadata, closure, pins, authorization, literals and integrity are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
