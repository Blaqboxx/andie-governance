#!/usr/bin/env python3
"""Evaluate adapter manifests against profile policy overlays.

Implements inheritance-aware profile resolution with deny precedence.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from tools.validate_adapter_manifest import _load_capability_enums, _load_json, validate_manifest

ALLOWED_ACTIONS = {"allow", "supervised", "deny"}
ALLOWED_RISK = {"low", "moderate", "high", "critical"}
RISK_ORDER = ["low", "moderate", "high", "critical"]
BLAST_ORDER = ["service", "host", "cluster", "region", "global"]
ACTION_RANK = {"allow": 0, "supervised": 1, "deny": 2}


def _list_union(parent: list[str], child: list[str]) -> list[str]:
    seen: set[str] = set()
    merged: list[str] = []
    for value in parent + child:
        if value not in seen:
            seen.add(value)
            merged.append(value)
    return merged


def _more_restrictive_action(left: str, right: str) -> str:
    return left if ACTION_RANK[left] >= ACTION_RANK[right] else right


def _scope_rank(scope: str) -> int:
    return BLAST_ORDER.index(scope)


def _validate_profile_shape(profile: dict[str, Any], source_name: str) -> list[str]:
    errors: list[str] = []
    required = {
        "schema_version",
        "profile",
        "inherits",
        "default_action",
        "dangerous_operations_default",
        "require_approval_for_risk_tiers",
        "max_blast_radius_scope",
        "deny_capabilities",
        "supervise_capabilities",
        "allow_capabilities",
        "adapter_constraints",
    }
    missing = required - set(profile.keys())
    if missing:
        errors.append(f"{source_name}: missing fields {sorted(missing)}")
    if profile.get("schema_version") != "1.0":
        errors.append(f"{source_name}: schema_version must be 1.0")
    if profile.get("default_action") not in ALLOWED_ACTIONS:
        errors.append(f"{source_name}: default_action must be one of {sorted(ALLOWED_ACTIONS)}")
    if profile.get("dangerous_operations_default") not in {"supervised", "deny"}:
        errors.append(f"{source_name}: dangerous_operations_default must be supervised or deny")
    risk_levels = profile.get("require_approval_for_risk_tiers", [])
    if not isinstance(risk_levels, list) or any(level not in ALLOWED_RISK for level in risk_levels):
        errors.append(f"{source_name}: require_approval_for_risk_tiers contains invalid values")
    if profile.get("max_blast_radius_scope") not in BLAST_ORDER:
        errors.append(f"{source_name}: max_blast_radius_scope must be one of {BLAST_ORDER}")

    for key in ["deny_capabilities", "supervise_capabilities", "allow_capabilities"]:
        value = profile.get(key)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            errors.append(f"{source_name}: {key} must be a list of strings")

    adapter_constraints = profile.get("adapter_constraints")
    if not isinstance(adapter_constraints, dict):
        errors.append(f"{source_name}: adapter_constraints must be an object")
    else:
        for adapter_id, constraints in adapter_constraints.items():
            if not isinstance(adapter_id, str) or not adapter_id:
                errors.append(f"{source_name}: adapter_constraints has invalid adapter id")
                continue
            if not isinstance(constraints, dict):
                errors.append(f"{source_name}: adapter constraint for {adapter_id} must be object")
                continue
            for key in ["deny_capabilities", "supervise_capabilities"]:
                if key in constraints:
                    value = constraints[key]
                    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                        errors.append(f"{source_name}: adapter_constraints.{adapter_id}.{key} must be list[str]")
            if "max_blast_radius_scope" in constraints and constraints["max_blast_radius_scope"] not in BLAST_ORDER:
                errors.append(f"{source_name}: adapter_constraints.{adapter_id}.max_blast_radius_scope invalid")

    return errors


def _load_profile(profile_name: str, profiles_dir: Path, stack: list[str] | None = None) -> dict[str, Any]:
    stack = stack or []
    if profile_name in stack:
        cycle = " -> ".join(stack + [profile_name])
        raise ValueError(f"profile inheritance cycle detected: {cycle}")

    path = profiles_dir / f"{profile_name}.json"
    if not path.exists():
        raise ValueError(f"profile file not found: {path}")

    raw = _load_json(path)
    if not isinstance(raw, dict):
        raise ValueError(f"profile must be object: {path}")

    shape_errors = _validate_profile_shape(raw, profile_name)
    if shape_errors:
        raise ValueError("; ".join(shape_errors))

    resolved = {
        "schema_version": "1.0",
        "profile": profile_name,
        "inherits": [],
        "default_action": "supervised",
        "dangerous_operations_default": "deny",
        "require_approval_for_risk_tiers": [],
        "max_blast_radius_scope": "cluster",
        "deny_capabilities": [],
        "supervise_capabilities": [],
        "allow_capabilities": [],
        "adapter_constraints": {},
    }

    parents = raw.get("inherits", [])
    if not isinstance(parents, list):
        raise ValueError(f"{profile_name}: inherits must be a list")

    for parent_name in parents:
        if not isinstance(parent_name, str) or not parent_name:
            raise ValueError(f"{profile_name}: inherits contains non-string name")
        parent = _load_profile(parent_name, profiles_dir, stack + [profile_name])
        resolved["require_approval_for_risk_tiers"] = _list_union(
            resolved["require_approval_for_risk_tiers"],
            parent["require_approval_for_risk_tiers"],
        )
        resolved["deny_capabilities"] = _list_union(resolved["deny_capabilities"], parent["deny_capabilities"])
        resolved["supervise_capabilities"] = _list_union(resolved["supervise_capabilities"], parent["supervise_capabilities"])
        resolved["allow_capabilities"] = _list_union(resolved["allow_capabilities"], parent["allow_capabilities"])
        resolved["default_action"] = parent["default_action"]
        resolved["dangerous_operations_default"] = parent["dangerous_operations_default"]
        resolved["max_blast_radius_scope"] = parent["max_blast_radius_scope"]

        for adapter_id, constraint in parent["adapter_constraints"].items():
            if adapter_id not in resolved["adapter_constraints"]:
                resolved["adapter_constraints"][adapter_id] = {
                    "deny_capabilities": [],
                    "supervise_capabilities": [],
                }
            current = resolved["adapter_constraints"][adapter_id]
            current["deny_capabilities"] = _list_union(current.get("deny_capabilities", []), constraint.get("deny_capabilities", []))
            current["supervise_capabilities"] = _list_union(current.get("supervise_capabilities", []), constraint.get("supervise_capabilities", []))
            if "max_blast_radius_scope" in constraint:
                current["max_blast_radius_scope"] = constraint["max_blast_radius_scope"]

    resolved["default_action"] = raw["default_action"]
    resolved["dangerous_operations_default"] = raw["dangerous_operations_default"]
    resolved["max_blast_radius_scope"] = raw["max_blast_radius_scope"]
    resolved["require_approval_for_risk_tiers"] = _list_union(resolved["require_approval_for_risk_tiers"], raw["require_approval_for_risk_tiers"])
    resolved["deny_capabilities"] = _list_union(resolved["deny_capabilities"], raw["deny_capabilities"])
    resolved["supervise_capabilities"] = _list_union(resolved["supervise_capabilities"], raw["supervise_capabilities"])
    resolved["allow_capabilities"] = _list_union(resolved["allow_capabilities"], raw["allow_capabilities"])

    for adapter_id, constraint in raw["adapter_constraints"].items():
        if adapter_id not in resolved["adapter_constraints"]:
            resolved["adapter_constraints"][adapter_id] = {
                "deny_capabilities": [],
                "supervise_capabilities": [],
            }
        current = resolved["adapter_constraints"][adapter_id]
        current["deny_capabilities"] = _list_union(current.get("deny_capabilities", []), constraint.get("deny_capabilities", []))
        current["supervise_capabilities"] = _list_union(current.get("supervise_capabilities", []), constraint.get("supervise_capabilities", []))
        if "max_blast_radius_scope" in constraint:
            current["max_blast_radius_scope"] = constraint["max_blast_radius_scope"]

    resolved["inherits"] = parents
    return resolved


def _action_from_manifest_profile(capability: dict[str, Any], profile_name: str) -> str:
    if profile_name == "prod":
        return str(capability.get("production_default", "supervised"))
    return "supervised" if bool(capability.get("requires_approval")) else "allow"


def evaluate_manifest_against_profile(
    manifest: dict[str, Any],
    profile_name: str,
    resolved_profile: dict[str, Any],
) -> dict[str, Any]:
    adapter_id = manifest.get("adapter_id")
    supported_profiles = manifest.get("governance", {}).get("policy_profiles_supported", [])

    profile_supported = profile_name in supported_profiles

    blast_scope = manifest.get("blast_radius", {}).get("scope", "global")
    global_max_scope = resolved_profile["max_blast_radius_scope"]
    adapter_constraints = resolved_profile["adapter_constraints"].get(adapter_id, {})
    adapter_max_scope = adapter_constraints.get("max_blast_radius_scope", global_max_scope)

    max_scope_rank = min(_scope_rank(global_max_scope), _scope_rank(adapter_max_scope))
    manifest_scope_rank = _scope_rank(blast_scope)

    blast_allowed = manifest_scope_rank <= max_scope_rank

    deny_list = set(resolved_profile["deny_capabilities"]) | set(adapter_constraints.get("deny_capabilities", []))
    supervise_list = set(resolved_profile["supervise_capabilities"]) | set(adapter_constraints.get("supervise_capabilities", []))
    allow_list = set(resolved_profile["allow_capabilities"])
    approval_risks = set(resolved_profile["require_approval_for_risk_tiers"])

    decisions: list[dict[str, str]] = []
    denied_count = 0

    for capability in manifest.get("capabilities", []):
        cap_id = str(capability.get("id", ""))
        risk_tier = str(capability.get("risk_tier", "low"))
        dangerous = bool(capability.get("dangerous", False))

        reasons: list[str] = []
        action = resolved_profile["default_action"]

        if cap_id in allow_list:
            action = "allow"
            reasons.append("profile allowlist")
        if cap_id in supervise_list:
            action = _more_restrictive_action(action, "supervised")
            reasons.append("profile supervision list")
        if risk_tier in approval_risks:
            action = _more_restrictive_action(action, "supervised")
            reasons.append("risk-tier approval requirement")
        if dangerous and resolved_profile["dangerous_operations_default"] == "deny":
            action = _more_restrictive_action(action, "deny")
            reasons.append("dangerous operation default deny")

        action = _more_restrictive_action(action, _action_from_manifest_profile(capability, profile_name))

        if cap_id in deny_list:
            action = "deny"
            reasons.append("deny precedence")

        if not profile_supported:
            action = "deny"
            reasons.append("manifest does not support target profile")
        if not blast_allowed:
            action = "deny"
            reasons.append("blast radius exceeds profile scope")

        if action == "deny":
            denied_count += 1

        decisions.append(
            {
                "capability": cap_id,
                "action": action,
                "risk_tier": risk_tier,
                "reasons": "; ".join(reasons) if reasons else "default policy action",
            }
        )

    return {
        "adapter_id": adapter_id,
        "profile": profile_name,
        "profile_supported": profile_supported,
        "blast_radius_scope": blast_scope,
        "max_allowed_scope": BLAST_ORDER[max_scope_rank],
        "blast_allowed": blast_allowed,
        "denied_capability_count": denied_count,
        "capability_decisions": decisions,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate adapter manifests against profile policy overlays.")
    parser.add_argument("paths", nargs="+", help="Manifest file paths")
    parser.add_argument("--profile", required=True, choices=["dev", "staging", "prod"], help="Target policy profile")
    parser.add_argument("--policies-dir", default="policies/profiles", help="Policy profile directory")
    parser.add_argument("--json", action="store_true", dest="json_output", help="Emit machine-readable output")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    base_dir = Path(__file__).resolve().parent.parent
    policies_dir = (base_dir / args.policies_dir).resolve()

    try:
        allowed_capabilities = _load_capability_enums(base_dir)
        resolved_profile = _load_profile(args.profile, policies_dir)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"ERROR: failed to initialize evaluator: {exc}")
        return 2

    outputs: list[dict[str, Any]] = []
    has_errors = False

    for raw_path in args.paths:
        path = Path(raw_path)
        if not path.exists():
            has_errors = True
            outputs.append({"path": raw_path, "valid": False, "errors": ["file not found"]})
            continue

        try:
            manifest = _load_json(path)
            if not isinstance(manifest, dict):
                raise ValueError("manifest root must be an object")

            manifest_errors = validate_manifest(manifest, allowed_capabilities)
            if manifest_errors:
                has_errors = True
                outputs.append(
                    {
                        "path": str(path),
                        "valid": False,
                        "manifest_errors": manifest_errors,
                    }
                )
                continue

            evaluation = evaluate_manifest_against_profile(manifest, args.profile, resolved_profile)
            outputs.append(
                {
                    "path": str(path),
                    "valid": True,
                    "evaluation": evaluation,
                }
            )
        except Exception as exc:  # pylint: disable=broad-except
            has_errors = True
            outputs.append({"path": str(path), "valid": False, "errors": [str(exc)]})

    if args.json_output:
        print(json.dumps({"profile": args.profile, "resolved_policy": resolved_profile, "results": outputs}, indent=2))
    else:
        print(f"Profile: {args.profile}")
        for result in outputs:
            if not result["valid"]:
                print(f"FAIL: {result['path']}")
                for key in ["errors", "manifest_errors"]:
                    for err in result.get(key, []):
                        print(f"  - {err}")
                continue

            eval_data = result["evaluation"]
            print(f"PASS: {result['path']}")
            print(
                f"  adapter={eval_data['adapter_id']} profile_supported={eval_data['profile_supported']} "
                f"blast_allowed={eval_data['blast_allowed']} denied={eval_data['denied_capability_count']}"
            )
            for item in eval_data["capability_decisions"]:
                print(f"  - {item['capability']}: {item['action']} ({item['reasons']})")

    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
