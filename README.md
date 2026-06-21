# Cloud Security Misconfiguration Checker

A Python cloud security misconfiguration checker that analyzes demo AWS-style JSON configuration files for public access, weak IAM policies, missing encryption, missing logging, and exposed services.

This project is designed for Security Engineer, Cloud Security, DevSecOps, SOC, and security automation portfolio workflows.

## Safety Notice

This tool does not connect to real cloud accounts.

It only analyzes local demo JSON files.

Do not commit real cloud account IDs, ARNs, bucket names, IAM policies, secrets, access keys, customer data, or production configuration files.

## Features

- Analyze AWS-style S3 bucket configs
- Analyze AWS-style security group configs
- Analyze AWS-style IAM policy configs
- Analyze AWS-style RDS/database configs
- Detect public S3 bucket access
- Detect missing encryption
- Detect missing logging
- Detect disabled versioning
- Detect security groups open to 0.0.0.0/0
- Detect risky exposed ports
- Detect wildcard IAM permissions
- Detect public database exposure
- Generate CSV report
- Generate TXT summary
- Generate JSON report
- Generate findings.json
- Generate events.ndjson
- Generate HTML report
- Include unit tests
- Include GitHub Actions workflow

## Project Structure

    cloud-security-misconfiguration-checker/
    ├── .github/
    │   └── workflows/
    │       └── python-check.yml
    ├── docs/
    │   ├── cloud-checks.md
    │   └── project-notes.md
    ├── reports/
    │   └── .gitkeep
    ├── sample_configs/
    │   ├── aws_iam_policy.json
    │   ├── aws_rds_instance.json
    │   ├── aws_s3_bucket.json
    │   └── aws_security_group.json
    ├── sample_outputs/
    ├── src/
    │   └── cloud_config_checker.py
    ├── tests/
    │   └── test_detection_logic.py
    ├── README.md
    ├── requirements.txt
    └── .gitignore

## Usage

Run the checker against the demo config files:

    python src/cloud_config_checker.py --input sample_configs --output reports --format all

Generate only HTML:

    python src/cloud_config_checker.py --input sample_configs --output reports --format html

Generate only JSON:

    python src/cloud_config_checker.py --input sample_configs --output reports --format json

## Generated Reports

The tool generates reports locally inside the reports folder:

- cloud_misconfiguration_report.csv
- cloud_misconfiguration_summary.txt
- cloud_misconfiguration_report.json
- findings.json
- events.ndjson
- cloud_misconfiguration_report.html

Generated report files are ignored by Git and should not be committed.

## Detection Logic

### S3 Bucket Misconfigurations

The tool checks for:

- Public access enabled
- Encryption disabled
- Logging disabled
- Versioning disabled

### Security Group Misconfigurations

The tool checks for:

- Inbound access from 0.0.0.0/0
- Public exposure of risky ports such as SSH, Telnet, SMB, RDP, database ports, and Redis

### IAM Policy Misconfigurations

The tool checks for:

- Wildcard actions
- Wildcard resources
- Full administrative access

### RDS / Database Misconfigurations

The tool checks for:

- Public accessibility enabled
- Encryption disabled
- Backups disabled
- Deletion protection disabled

## Risk Score Logic

| Severity | Points |
|---|---|
| Critical | 15 |
| High | 10 |
| Medium | 5 |
| Low | 2 |
| Info | 0 |

Risk level:

| Score | Risk Level |
|---|---|
| 30+ | Critical |
| 20-29 | High |
| 10-19 | Medium |
| 1-9 | Low |
| 0 | Info |

## Output Formats

### CSV

Used for spreadsheet-based review and filtering.

### TXT

Used for human-readable summaries.

### JSON

Used for automation, dashboards, APIs, and structured reporting.

### findings.json

Used for security finding workflows.

### events.ndjson

Used for SIEM-style ingestion.

### HTML

Used for readable reports that can be opened in a browser.

## GitHub Actions

This project includes a GitHub Actions workflow that runs automated checks on every push and pull request.

The workflow:

- Checks Python syntax
- Runs unit tests
- Runs the cloud config checker
- Verifies that reports can be generated successfully

Workflow file:

    .github/workflows/python-check.yml

## Requirements

No external dependencies are required.

This project uses only Python standard library modules.

## Run Tests

    python -m unittest discover -s tests

## Privacy

All sample configuration files use demo-safe names.

This repository should not contain:

- Real cloud account IDs
- Real ARNs
- Real bucket names
- Real IAM policies
- Real access keys
- Real secrets
- Real customer data
- Real production configuration files

## Skills Demonstrated

- Python automation
- Cloud security basics
- Misconfiguration detection
- IAM policy review
- Public access review
- Security group exposure analysis
- Encryption and logging checks
- Security reporting
- Risk scoring
- CSV report generation
- TXT summary generation
- JSON report generation
- NDJSON event generation
- HTML report generation
- Unit testing
- GitHub Actions
- DevSecOps-style workflow
- Security Engineer workflow

## Example Resume Description

Built a Python cloud security misconfiguration checker that analyzes demo AWS-style JSON configs for public access, weak IAM policies, missing encryption, missing logging, exposed services, and public databases, generating CSV/TXT/JSON/NDJSON/HTML reports with unit tests and GitHub Actions.
