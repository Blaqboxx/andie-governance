# andie-governance

ANDIE Governance owns policy validation and compliance-grade controls.

## Scope

- policy schemas
- validator CLI
- capability enums
- governance templates
- environment profiles
- policy inheritance tooling
- compliance-grade validation

## Guarantees

- strict schema validation
- deterministic policy inheritance
- explicit capability-scope enforcement
- profile-aware restrictions (dev, staging, prod)
- audit-friendly validation output

## Production Defaults

- supervised approval
- strict capability scopes
- rollback-first behavior
- telemetry-verified stabilization
- deny-by-default dangerous operations

## Adapter Manifest Validator

Validate adapter manifests against capability enums and governance rules:

```bash
python3 tools/validate_adapter_manifest.py ../andie-adapters/manifests/*.adapter.json
```

Optional machine-readable output:

```bash
python3 tools/validate_adapter_manifest.py --json ../andie-adapters/manifests/*.adapter.json
```

## Profile Policy Overlay Engine

Profile templates are defined in `policies/profiles/` and support inheritance and deny precedence.

Evaluate adapters against environment policy overlays:

```bash
python3 tools/evaluate_policy_overlay.py --profile dev ../andie-adapters/manifests/*.adapter.json
python3 tools/evaluate_policy_overlay.py --profile staging ../andie-adapters/manifests/*.adapter.json
python3 tools/evaluate_policy_overlay.py --profile prod ../andie-adapters/manifests/*.adapter.json
```

Optional machine-readable output:

```bash
python3 tools/evaluate_policy_overlay.py --profile prod --json ../andie-adapters/manifests/*.adapter.json
```

Overlay evaluation enforces:

- profile inheritance
- deny precedence over allow/supervised actions
- adapter-specific capability suppression
- blast-radius scope restrictions
- profile compatibility checks
