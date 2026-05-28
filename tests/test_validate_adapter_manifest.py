import json
import tempfile
import unittest
from pathlib import Path

from tools.validate_adapter_manifest import _load_capability_enums, validate_manifest


class ValidateAdapterManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base_dir = Path(__file__).resolve().parent.parent
        cls.allowed = _load_capability_enums(base_dir)

    def test_valid_manifest(self):
        manifest = {
            "schema_version": "1.0",
            "adapter_id": "docker",
            "display_name": "Docker Adapter",
            "version": "1.0.0",
            "audited": True,
            "execution": {
                "dry_run_supported": True,
                "rollback": {"feasible": True, "strategies": ["restart_previous_container"]}
            },
            "capabilities": [
                {
                    "id": "docker.container.restart",
                    "operation": "restart container",
                    "scope": "restart",
                    "risk_tier": "high",
                    "dangerous": True,
                    "production_default": "supervised",
                    "requires_approval": True,
                    "audit_classification": "sensitive_change"
                }
            ],
            "blast_radius": {
                "scope": "service",
                "reversible": True,
                "max_affected_units": 1
            },
            "telemetry_requirements": [
                {
                    "signal": "container_health",
                    "source": "docker_events",
                    "required_for_verify": True,
                    "stabilization_window_seconds": 300
                }
            ],
            "governance": {
                "policy_profiles_supported": ["dev", "staging", "prod"],
                "least_privilege": True,
                "deny_by_default_dangerous": True
            }
        }

        errors = validate_manifest(manifest, self.allowed)
        self.assertEqual([], errors)

    def test_unknown_capability_fails(self):
        manifest = {
            "schema_version": "1.0",
            "adapter_id": "custom",
            "display_name": "Custom Adapter",
            "version": "1.0.0",
            "audited": True,
            "execution": {
                "dry_run_supported": True,
                "rollback": {"feasible": True, "strategies": ["noop"]}
            },
            "capabilities": [
                {
                    "id": "custom.nonexistent",
                    "operation": "do thing",
                    "scope": "configure",
                    "risk_tier": "moderate",
                    "dangerous": False,
                    "production_default": "supervised",
                    "requires_approval": False,
                    "audit_classification": "change"
                }
            ],
            "blast_radius": {
                "scope": "service",
                "reversible": True,
                "max_affected_units": 1
            },
            "telemetry_requirements": [
                {
                    "signal": "x",
                    "source": "y",
                    "required_for_verify": True,
                    "stabilization_window_seconds": 60
                }
            ],
            "governance": {
                "policy_profiles_supported": ["dev"],
                "least_privilege": True,
                "deny_by_default_dangerous": True
            }
        }

        errors = validate_manifest(manifest, self.allowed)
        self.assertTrue(any("not in capability enum list" in msg for msg in errors))

    def test_high_risk_allow_fails(self):
        manifest = {
            "schema_version": "1.0",
            "adapter_id": "redis",
            "display_name": "Redis Adapter",
            "version": "1.0.0",
            "audited": True,
            "execution": {
                "dry_run_supported": True,
                "rollback": {"feasible": True, "strategies": ["restore_rdb"]}
            },
            "capabilities": [
                {
                    "id": "redis.flushdb",
                    "operation": "flush db",
                    "scope": "recover",
                    "risk_tier": "critical",
                    "dangerous": True,
                    "production_default": "allow",
                    "requires_approval": True,
                    "audit_classification": "destructive"
                }
            ],
            "blast_radius": {
                "scope": "service",
                "reversible": False,
                "max_affected_units": 1
            },
            "telemetry_requirements": [
                {
                    "signal": "key_count",
                    "source": "redis_info",
                    "required_for_verify": True,
                    "stabilization_window_seconds": 120
                }
            ],
            "governance": {
                "policy_profiles_supported": ["prod"],
                "least_privilege": True,
                "deny_by_default_dangerous": True
            }
        }

        errors = validate_manifest(manifest, self.allowed)
        self.assertTrue(any("cannot default to allow" in msg for msg in errors))

    def test_validator_cli_json_output(self):
        base_dir = Path(__file__).resolve().parent.parent
        script_path = base_dir / "tools" / "validate_adapter_manifest.py"
        payload = {
            "schema_version": "1.0",
            "adapter_id": "systemd",
            "display_name": "systemd Adapter",
            "version": "1.0.0",
            "audited": True,
            "execution": {
                "dry_run_supported": True,
                "rollback": {"feasible": True, "strategies": ["restart_prior_unit_state"]}
            },
            "capabilities": [
                {
                    "id": "systemd.unit.status",
                    "operation": "unit status",
                    "scope": "observe",
                    "risk_tier": "low",
                    "dangerous": False,
                    "production_default": "allow",
                    "requires_approval": False,
                    "audit_classification": "read"
                }
            ],
            "blast_radius": {
                "scope": "host",
                "reversible": True,
                "max_affected_units": 1
            },
            "telemetry_requirements": [
                {
                    "signal": "unit_active_state",
                    "source": "systemd_dbus",
                    "required_for_verify": True,
                    "stabilization_window_seconds": 45
                }
            ],
            "governance": {
                "policy_profiles_supported": ["dev", "staging", "prod"],
                "least_privilege": True,
                "deny_by_default_dangerous": True
            }
        }

        with tempfile.TemporaryDirectory() as tmp:
            manifest_path = Path(tmp) / "manifest.json"
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            exit_code = __import__("subprocess").run(
                ["python3", str(script_path), "--json", str(manifest_path)],
                check=False,
                cwd=str(base_dir),
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, exit_code.returncode, msg=exit_code.stderr)
            output = json.loads(exit_code.stdout)
            self.assertTrue(output["results"][0]["valid"])


if __name__ == "__main__":
    unittest.main()
