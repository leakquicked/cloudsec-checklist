# CloudSec Checklist

Offline, provider-neutral checklist for reviewing a **sanitized JSON snapshot** of cloud security settings.

## Checks
Public storage access, audit logging, MFA, encryption at rest/in transit, least privilege and backups.

## Run
Python 3.10+; no third-party dependencies.

```bash
python cloudsec_check.py example_snapshot.json
python cloudsec_check.py example_snapshot.json --output review.json
python -m unittest discover -s tests -v
```

## Snapshot format
See `example_snapshot.json`. Missing values are reported as `unknown`, not as secure or insecure. A `review` finding means the observed value differs from the checklist's expected value.

## Important
This tool does not connect to AWS, Azure, Google Cloud or any other provider. It does not validate live cloud state, IAM policies or compliance. Adapt the checklist to your architecture and provider guidance. Do not place credentials, tokens, account identifiers or sensitive infrastructure details in public snapshots.
