import unittest
from pathlib import Path

from tools.evaluate_policy_overlay import _load_profile, evaluate_manifest_against_profile


class EvaluatePolicyOverlayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = Path(__file__).resolve().parent.parent
        cls.policies_dir = cls.base_dir / "policies" / "profiles"

    def test_profile_inheritance_and_deny_precedence(self):
        resolved = _load_profile("prod", self.policies_dir)

        manifest = {
            "adapter_id": "docker",
            "governance": {"policy_profiles_supported": ["dev", "staging", "prod"]},
            "blast_radius": {"scope": "host"},
            "capabilities": [
                {
                    "id": "docker.container.inspect",
                    "risk_tier": "low",
                    "dangerous": False,
                    "production_default": "allow",
                    "requires_approval": False,
                },
                {
                    "id": "docker.volume.prune",
                    "risk_tier": "critical",
                    "dangerous": True,
                    "production_default": "deny",
                    "requires_approval": True,
                },
            ],
        }

        evaluation = evaluate_manifest_against_profile(manifest, "prod", resolved)
        by_id = {item["capability"]: item for item in evaluation["capability_decisions"]}

        self.assertEqual("allow", by_id["docker.container.inspect"]["action"])
        self.assertEqual("deny", by_id["docker.volume.prune"]["action"])
        self.assertIn("deny precedence", by_id["docker.volume.prune"]["reasons"])

    def test_blast_radius_restriction_forces_denial(self):
        resolved = _load_profile("prod", self.policies_dir)

        manifest = {
            "adapter_id": "docker",
            "governance": {"policy_profiles_supported": ["prod"]},
            "blast_radius": {"scope": "region"},
            "capabilities": [
                {
                    "id": "docker.container.inspect",
                    "risk_tier": "low",
                    "dangerous": False,
                    "production_default": "allow",
                    "requires_approval": False,
                }
            ],
        }

        evaluation = evaluate_manifest_against_profile(manifest, "prod", resolved)
        self.assertFalse(evaluation["blast_allowed"])
        self.assertEqual("deny", evaluation["capability_decisions"][0]["action"])
        self.assertIn("blast radius exceeds profile scope", evaluation["capability_decisions"][0]["reasons"])

    def test_profile_compatibility_denial(self):
        resolved = _load_profile("staging", self.policies_dir)

        manifest = {
            "adapter_id": "ssh",
            "governance": {"policy_profiles_supported": ["dev", "prod"]},
            "blast_radius": {"scope": "host"},
            "capabilities": [
                {
                    "id": "ssh.command.readonly",
                    "risk_tier": "low",
                    "dangerous": False,
                    "production_default": "allow",
                    "requires_approval": False,
                }
            ],
        }

        evaluation = evaluate_manifest_against_profile(manifest, "staging", resolved)
        self.assertFalse(evaluation["profile_supported"])
        self.assertEqual("deny", evaluation["capability_decisions"][0]["action"])
        self.assertIn("manifest does not support target profile", evaluation["capability_decisions"][0]["reasons"])


if __name__ == "__main__":
    unittest.main()
