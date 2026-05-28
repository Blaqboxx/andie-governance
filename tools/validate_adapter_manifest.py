#!/usr/bin/env python3
"""Validate ANDIE adapter manifests against governance rules.

This validator is dependency-free by design so it can run in minimal environments.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "1.0"
ALLOWED_SCOPE = {"observe", "diagnose", "configure", "restart", "recover", "rollback"}
ALLOWED_RISK = {"low", "moderate", "high", "critical"}
ALLOWED_PROD_DEFAULT = {"deny", "supervised", "allow"}
ALLOWED_AUDIT = {"read", "change", "sensitive_change", "destructive"}
ALLOWED_BLAST_SCOPE = {"service", "host", "cluster", "region", "global"}
ALLOWED_PROFILES = {"dev", "staging", "prod"}

REQUIRED_ROOT_KEYS = {
    "schema_version",
    "adapter_id",
    "display_name",
    "version",
    "audited",
    "execution",
    "capabilities",
    "blast_radius",
    "telemetry_requirements",
    "governance",
}


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc


def _load_capability_enums(base_dir: Path) -> set[str]:
    enum_path = base_dir / "capabilities" / "capability_enums.json"
    payload = _load_json(enum_path)
    capabilities = payload.get("capabilities", [])
    if not isinstance(capabilities, list) or not all(isinstance(v, str) for v in capabilities):
        raise ValueError("capability_enums.json must contain a string array under 'capabilities'")
    return set(capabilities)


def _expect(condition: bool, message: str, errors: list[str]) -> None:
    if not condition:
        errors.append(message)


def validate_manifest(manifest: dict[str, Any], allowed_capabilities: set[str]) -> list[str]:
    errors: list[str] = []

    _expect(isinstance(manifest, dict), "manifest root must be an object", errors)
    if errors:
        return errors

    for key in REQUIRED_ROOT_KEYS:
        _expect(key in manifest, f"missing required field: {key}", errors)

    extra = set(manifest.keys()) - REQUIRED_ROOT_KEYS
    if extra:
        errors.append(f"unknown top-level fields: {sorted(extra)}")

    if errors:
        return errors

    _expect(manifest["schema_version"] == SCHEMA_VERSION, "schema_version must be 1.0", errors)
    _expect(isinstance(manifest["adapter_id"], str) and bool(manifest["adapter_id"]), "adapter_id must be a non-empty string", errors)
    _expect(isinstance(manifest["display_name"], str) and len(manifest["display_name"]) >= 3, "display_name must be at least 3 characters", errors)
    _expect(isinstance(manifest["version"], str) and manifest["version"].count(".") == 2, "version must be semver-like (x.y.z)", errors)
    _expect(isinstance(manifest["audited"], bool), "audited must be boolean", errors)

    execution = manifest["execution"]
    _expect(isinstance(execution, dict), "execution must be an object", errors)
    if isinstance(execution, dict):
        _expect("dry_run_supported" in execution and isinstance(execution["dry_run_supported"], bool), "execution.dry_run_supported must be boolean", errors)
        rollback = execution.get("rollback")
        _expect(isinstance(rollback, dict), "execution.rollback must be an object", errors)
        if isinstance(rollback, dict):
            _expect(isinstance(rollback.get("feasible"), bool), "execution.rollback.feasible must be boolean", errors)
            strategies = rollback.get("strategies")
            _expect(isinstance(strategies, list) and len(strategies) >= 1 and all(isinstance(v, str) and v for v in strategies), "execution.rollback.strategies must be a non-empty string array", errors)

    capabilities = manifest["capabilities"]
    _expect(isinstance(capabilities, list) and len(capabilities) >= 1, "capabilities must be a non-empty array", errors)

    if isinstance(capabilities, list):
        for idx, capability in enumerate(capabilities):
            prefix = f"capabilities[{idx}]"
            _expect(isinstance(capability, dict), f"{prefix} must be an object", errors)
            if not isinstance(capability, dict):
                continue

            required = {
                "id",
                "operation",
                "scope",
                "risk_tier",
                "dangerous",
                "production_default",
                "requires_approval",
                "audit_classification",
            }
            missing = required - set(capability.keys())
            if missing:
                errors.append(f"{prefix} missing required fields: {sorted(missing)}")
                continue

            _expect(capability["id"] in allowed_capabilities, f"{prefix}.id is not in capability enum list: {capability['id']}", errors)
            _expect(isinstance(capability["operation"], str) and bool(capability["operation"]), f"{prefix}.operation must be non-empty string", errors)
            _expect(capability["scope"] in ALLOWED_SCOPE, f"{prefix}.scope invalid: {capability['scope']}", errors)
            _expect(capability["risk_tier"] in ALLOWED_RISK, f"{prefix}.risk_tier invalid: {capability['risk_tier']}", errors)
            _expect(isinstance(capability["dangerous"], bool), f"{prefix}.dangerous must be boolean", errors)
            _expect(capability["production_default"] in ALLOWED_PROD_DEFAULT, f"{prefix}.production_default invalid: {capability['production_default']}", errors)
            _expect(isinstance(capability["requires_approval"], bool), f"{prefix}.requires_approval must be boolean", errors)
            _expect(capability["audit_classification"] in ALLOWED_AUDIT, f"{prefix}.audit_classification invalid: {capability['audit_classification']}", errors)

            if capability["risk_tier"] in {"high", "critical"}:
                _expect(capability["production_default"] in {"deny", "supervised"}, f"{prefix} high/critical risk cannot default to allow in prod", errors)
                _expect(capability["requires_approval"] is True, f"{prefix} high/critical risk must require approval", errors)

            if capability["dangerous"]:
                _expect(capability["production_default"] in {"deny", "supervised"}, f"{prefix} dangerous operation must be deny/supervised in prod", errors)

    blast = manifest["blast_radius"]
    _expect(isinstance(blast, dict), "blast_radius must be an object", errors)
    if isinstance(blast, dict):
        _expect(blast.get("scope") in ALLOWED_BLAST_SCOPE, f"blast_radius.scope must be one of {sorted(ALLOWED_BLAST_SCOPE)}", errors)
        _expect(isinstance(blast.get("reversible"), bool), "blast_radius.reversible must be boolean", errors)
        _expect(isinstance(blast.get("max_affected_units"), int) and blast.get("max_affected_units", 0) >= 1, "blast_radius.max_affected_units must be integer >= 1", errors)

    telemetry = manifest["telemetry_requirements"]
    _expect(isinstance(telemetry, list) and len(telemetry) >= 1, "telemetry_requirements must be non-empty array", errors)
    has_verification_signal = False
    if isinstance(telemetry, list):
        for idx, signal in enumerate(telemetry):
            prefix = f"telemetry_requirements[{idx}]"
            _expect(isinstance(signal, dict), f"{prefix} must be object", errors)
            if not isinstance(signal, dict):
                continue
            _expect(isinstance(signal.get("signal"), str) and bool(signal.get("signal")), f"{prefix}.signal must be non-empty string", errors)
            _expect(isinstance(signal.get("source"), str) and bool(signal.get("source")), f"{prefix}.source must be non-empty string", errors)
            _expect(isinstance(signal.get("required_for_verify"), bool), f"{prefix}.required_for_verify must be boolean", errors)
            _expect(isinstance(signal.get("stabilization_window_seconds"), int) and signal.get("stabilization_window_seconds", 0) >= 1, f"{prefix}.stabilization_window_seconds must be integer >= 1", errors)
            has_verification_signal = has_verification_signal or bool(signal.get("required_for_verify"))

    _expect(has_verification_signal, "telemetry_requirements must include at least one required_for_verify=true signal", errors)

    governance = manifest["governance"]
    _expect(isinstance(governance, dict), "governance must be an object", errors)
    if isinstance(governance, dict):
        profiles = governance.get("policy_profiles_supported")
        _expect(isinstance(profiles, list) and len(profiles) >= 1, "governance.policy_profiles_supported must be non-empty array", errors)
        if isinstance(profiles, list):
            invalid_profiles = [value for value in profiles if value not in ALLOWED_PROFILES]
            _expect(not invalid_profiles, f"governance.policy_profiles_supported has invalid values: {invalid_profiles}", errors)
        _expect(governance.get("least_privilege") is True, "governance.least_privilege must be true", errors)
        _expect(governance.get("deny_by_default_dangerous") is True, "governance.deny_by_default_dangerous must be true", errors)

    has_mutating_scope = False
    if isinstance(capabilities, list):
        for capability in capabilities:
            if isinstance(capability, dict) and capability.get("scope") in {"configure", "restart", "recover", "rollback"}:
                has_mutating_scope = True
                break

    if has_mutating_scope and isinstance(execution, dict):
        rollback = execution.get("rollback")
        if isinstance(rollback, dict):
            _expect(rollback.get("feasible") is True, "mutating adapters must declare execution.rollback.feasible=true", errors)

    return errors


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate ANDIE adapter manifest files.")
    parser.add_argument("paths", nargs="+", help="Manifest file paths to validate")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit machine-readable JSON results")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    base_dir = Path(__file__).resolve().parent.parent

    try:
        capability_set = _load_capability_enums(base_dir)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"ERROR: failed to load capability enum list: {exc}", file=sys.stderr)
        return 2

    results: list[dict[str, Any]] = []
    has_errors = False

    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.exists():
            has_errors = True
            results.append({"path": raw_path, "valid": False, "errors": ["file not found"]})
            continue

        try:
            manifest = _load_json(path)
            if not isinstance(manifest, dict):
                raise ValueError("manifest root must be an object")
            errors = validate_manifest(manifest, capability_set)
        except Exception as exc:  # pylint: disable=broad-except
            errors = [str(exc)]

        valid = len(errors) == 0
        has_errors = has_errors or (not valid)
        results.append({"path": str(path), "valid": valid, "errors": errors})

    if args.json_output:
        print(json.dumps({"results": results}, indent=2))
    else:
        for result in results:
            if result["valid"]:
                print(f"PASS: {result['path']}")
            else:
                print(f"FAIL: {result['path']}")
                for err in result["errors"]:
                    print(f"  - {err}")

    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
