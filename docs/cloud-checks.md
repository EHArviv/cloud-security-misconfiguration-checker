# Cloud Security Checks

This project checks demo AWS-style configuration files for common cloud security misconfigurations.

## S3 Bucket Checks

- Public access enabled
- Encryption disabled
- Logging disabled
- Versioning disabled

## Security Group Checks

- Inbound access from 0.0.0.0/0
- Risky public ports such as SSH, Telnet, SMB, RDP, database ports, and Redis

## IAM Policy Checks

- Wildcard actions
- Wildcard resources
- Full administrative access using action * and resource *

## RDS / Database Checks

- Public accessibility enabled
- Encryption disabled
- Backups disabled
- Deletion protection disabled

## Output Formats

The tool generates:

- CSV
- TXT
- JSON
- findings.json
- events.ndjson
- HTML

## Important Note

This is not a full CSPM platform.

It is a portfolio-friendly static config checker designed to demonstrate cloud security logic, reporting, and automation.
