from pathlib import Path
from datetime import datetime, timezone
import argparse
import csv
import html
import json


SEVERITY_POINTS = {
    "Critical": 15,
    "High": 10,
    "Medium": 5,
    "Low": 2,
    "Info": 0,
}


def load_json_file(file_path: Path) -> dict:
    with file_path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_configs(config_dir: Path) -> list[dict]:
    configs = []

    for file_path in sorted(config_dir.glob("*.json")):
        config = load_json_file(file_path)
        config["_source_file"] = str(file_path)
        configs.append(config)

    return configs


def create_finding(
    name: str,
    resource_type: str,
    resource_id: str,
    severity: str,
    details: str,
    recommendation: str,
) -> dict:
    return {
        "name": name,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "severity": severity,
        "details": details,
        "recommendation": recommendation,
        "status": "Open",
    }


def check_s3_bucket(config: dict) -> list[dict]:
    findings = []
    resource_type = config.get("resource_type", "unknown")
    resource_id = config.get("resource_id", "unknown")

    if config.get("public_access") is True:
        findings.append(create_finding(
            "S3 Bucket Allows Public Access",
            resource_type,
            resource_id,
            "High",
            "The S3 bucket is configured with public access enabled.",
            "Disable public access unless there is a documented business requirement."
        ))

    if config.get("encryption_enabled") is False:
        findings.append(create_finding(
            "S3 Bucket Missing Encryption",
            resource_type,
            resource_id,
            "Medium",
            "The S3 bucket does not have encryption enabled.",
            "Enable server-side encryption for stored objects."
        ))

    if config.get("logging_enabled") is False:
        findings.append(create_finding(
            "S3 Bucket Logging Disabled",
            resource_type,
            resource_id,
            "Low",
            "The S3 bucket does not have access logging enabled.",
            "Enable access logging for monitoring and investigation."
        ))

    if config.get("versioning_enabled") is False:
        findings.append(create_finding(
            "S3 Bucket Versioning Disabled",
            resource_type,
            resource_id,
            "Low",
            "The S3 bucket does not have versioning enabled.",
            "Enable versioning to help protect against accidental deletion or overwrite."
        ))

    return findings


def check_security_group(config: dict) -> list[dict]:
    findings = []
    resource_type = config.get("resource_type", "unknown")
    resource_id = config.get("resource_id", "unknown")

    risky_ports = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        445: "SMB",
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
    }

    for rule in config.get("rules", []):
        cidr = rule.get("cidr", "")
        port = rule.get("port")
        protocol = rule.get("protocol", "unknown")

        if cidr == "0.0.0.0/0" and port in risky_ports:
            findings.append(create_finding(
                f"Security Group Exposes {risky_ports[port]} to the Internet",
                resource_type,
                resource_id,
                "High",
                f"{protocol.upper()} port {port} is open to 0.0.0.0/0.",
                "Restrict access to trusted IP ranges, VPN, or private networks."
            ))

        elif cidr == "0.0.0.0/0":
            findings.append(create_finding(
                "Security Group Allows Public Inbound Access",
                resource_type,
                resource_id,
                "Medium",
                f"{protocol.upper()} port {port} is open to 0.0.0.0/0.",
                "Confirm that public access is required and restrict scope where possible."
            ))

    return findings


def check_iam_policy(config: dict) -> list[dict]:
    findings = []
    resource_type = config.get("resource_type", "unknown")
    resource_id = config.get("resource_id", "unknown")

    for statement in config.get("statements", []):
        effect = statement.get("effect", "")
        actions = statement.get("actions", [])
        resources = statement.get("resources", [])

        if effect == "Allow" and "*" in actions and "*" in resources:
            findings.append(create_finding(
                "IAM Policy Allows Full Administrative Access",
                resource_type,
                resource_id,
                "Critical",
                "The IAM policy allows all actions on all resources.",
                "Apply least privilege and replace wildcard permissions with specific required actions and resources."
            ))

        elif effect == "Allow" and "*" in actions:
            findings.append(create_finding(
                "IAM Policy Uses Wildcard Actions",
                resource_type,
                resource_id,
                "High",
                "The IAM policy allows wildcard actions.",
                "Replace wildcard actions with the minimum required permissions."
            ))

        elif effect == "Allow" and "*" in resources:
            findings.append(create_finding(
                "IAM Policy Uses Wildcard Resources",
                resource_type,
                resource_id,
                "Medium",
                "The IAM policy applies permissions to all resources.",
                "Restrict resources to the required ARNs or resource identifiers."
            ))

    return findings


def check_rds_instance(config: dict) -> list[dict]:
    findings = []
    resource_type = config.get("resource_type", "unknown")
    resource_id = config.get("resource_id", "unknown")

    if config.get("publicly_accessible") is True:
        findings.append(create_finding(
            "Database Instance Publicly Accessible",
            resource_type,
            resource_id,
            "High",
            "The database instance is configured as publicly accessible.",
            "Disable public accessibility and place the database in a private subnet."
        ))

    if config.get("encryption_enabled") is False:
        findings.append(create_finding(
            "Database Encryption Disabled",
            resource_type,
            resource_id,
            "Medium",
            "The database instance does not have encryption enabled.",
            "Enable encryption at rest for the database."
        ))

    if config.get("backup_enabled") is False:
        findings.append(create_finding(
            "Database Backups Disabled",
            resource_type,
            resource_id,
            "Medium",
            "The database instance does not have backups enabled.",
            "Enable automated backups according to recovery requirements."
        ))

    if config.get("deletion_protection") is False:
        findings.append(create_finding(
            "Database Deletion Protection Disabled",
            resource_type,
            resource_id,
            "Low",
            "The database instance does not have deletion protection enabled.",
            "Enable deletion protection for production or critical databases."
        ))

    return findings


def check_config(config: dict) -> list[dict]:
    resource_type = config.get("resource_type", "")

    if resource_type == "aws_s3_bucket":
        return check_s3_bucket(config)

    if resource_type == "aws_security_group":
        return check_security_group(config)

    if resource_type == "aws_iam_policy":
        return check_iam_policy(config)

    if resource_type == "aws_rds_instance":
        return check_rds_instance(config)

    return []


def calculate_risk_score(findings: list[dict]) -> int:
    score = 0

    for finding in findings:
        score += SEVERITY_POINTS.get(finding.get("severity", "Info"), 0)

    return score


def calculate_overall_risk_level(score: int) -> str:
    if score >= 30:
        return "Critical"
    if score >= 20:
        return "High"
    if score >= 10:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def build_report(configs: list[dict], findings: list[dict]) -> dict:
    generated_at = datetime.now(timezone.utc).isoformat()
    risk_score = calculate_risk_score(findings)
    risk_level = calculate_overall_risk_level(risk_score)

    severity_counts = {
        "Critical": sum(1 for item in findings if item["severity"] == "Critical"),
        "High": sum(1 for item in findings if item["severity"] == "High"),
        "Medium": sum(1 for item in findings if item["severity"] == "Medium"),
        "Low": sum(1 for item in findings if item["severity"] == "Low"),
        "Info": sum(1 for item in findings if item["severity"] == "Info"),
    }

    return {
        "tool_name": "Cloud Security Misconfiguration Checker",
        "generated_at": generated_at,
        "summary": {
            "total_configs": len(configs),
            "total_findings": len(findings),
            "risk_score": risk_score,
            "overall_risk_level": risk_level,
            "severity_counts": severity_counts,
        },
        "findings": findings,
    }


def write_csv_report(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "cloud_misconfiguration_report.csv"

    with output_file.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "Name",
            "Resource Type",
            "Resource ID",
            "Severity",
            "Details",
            "Recommendation",
            "Status",
        ])

        for finding in report["findings"]:
            writer.writerow([
                finding["name"],
                finding["resource_type"],
                finding["resource_id"],
                finding["severity"],
                finding["details"],
                finding["recommendation"],
                finding["status"],
            ])


def write_json_report(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "cloud_misconfiguration_report.json"

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(report, file, indent=2)


def write_findings_json(findings: list[dict], output_dir: Path) -> None:
    output_file = output_dir / "findings.json"
    numbered_findings = []

    for index, finding in enumerate(findings, start=1):
        finding_copy = dict(finding)
        finding_copy["id"] = f"FINDING-{index:03}"
        numbered_findings.append(finding_copy)

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(numbered_findings, file, indent=2)


def write_ndjson_events(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "events.ndjson"

    with output_file.open("w", encoding="utf-8") as file:
        for finding in report["findings"]:
            event = {
                "timestamp": report["generated_at"],
                "event_type": "cloud_misconfiguration",
                "resource_type": finding["resource_type"],
                "resource_id": finding["resource_id"],
                "finding_name": finding["name"],
                "severity": finding["severity"],
                "message": finding["details"],
                "recommendation": finding["recommendation"],
            }
            file.write(json.dumps(event) + "\n")


def write_txt_summary(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "cloud_misconfiguration_summary.txt"
    summary = report["summary"]

    lines = [
        "Cloud Security Misconfiguration Summary",
        "=======================================",
        "",
        f"Generated At: {report['generated_at']}",
        f"Total Configs: {summary['total_configs']}",
        f"Total Findings: {summary['total_findings']}",
        f"Risk Score: {summary['risk_score']}",
        f"Overall Risk Level: {summary['overall_risk_level']}",
        "",
        "Severity Counts",
        "---------------",
    ]

    for severity, count in summary["severity_counts"].items():
        lines.append(f"{severity}: {count}")

    lines.extend([
        "",
        "Findings",
        "--------",
    ])

    for finding in report["findings"]:
        lines.extend([
            "",
            f"Name: {finding['name']}",
            f"Resource Type: {finding['resource_type']}",
            f"Resource ID: {finding['resource_id']}",
            f"Severity: {finding['severity']}",
            f"Details: {finding['details']}",
            f"Recommendation: {finding['recommendation']}",
            f"Status: {finding['status']}",
        ])

    output_file.write_text("\n".join(lines), encoding="utf-8")


def write_html_report(report: dict, output_dir: Path) -> None:
    output_file = output_dir / "cloud_misconfiguration_report.html"

    def esc(value: object) -> str:
        return html.escape(str(value))

    rows = ""

    for finding in report["findings"]:
        rows += f"""
        <tr>
          <td>{esc(finding["name"])}</td>
          <td>{esc(finding["resource_type"])}</td>
          <td>{esc(finding["resource_id"])}</td>
          <td>{esc(finding["severity"])}</td>
          <td>{esc(finding["details"])}</td>
          <td>{esc(finding["recommendation"])}</td>
          <td>{esc(finding["status"])}</td>
        </tr>
        """

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Cloud Security Misconfiguration Report</title>
  <style>
    body {{
      font-family: Arial, sans-serif;
      margin: 40px;
      background: #f7f7f7;
      color: #222;
    }}
    .container {{
      max-width: 1200px;
      margin: auto;
      background: #fff;
      padding: 32px;
      border-radius: 12px;
      border: 1px solid #ddd;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 20px;
    }}
    th, td {{
      border: 1px solid #ddd;
      padding: 10px;
      vertical-align: top;
      text-align: left;
    }}
    th {{
      background: #f0f0f0;
    }}
  </style>
</head>
<body>
  <div class="container">
    <h1>Cloud Security Misconfiguration Report</h1>

    <p><strong>Generated At:</strong> {esc(report["generated_at"])}</p>
    <p><strong>Total Configs:</strong> {esc(report["summary"]["total_configs"])}</p>
    <p><strong>Total Findings:</strong> {esc(report["summary"]["total_findings"])}</p>
    <p><strong>Risk Score:</strong> {esc(report["summary"]["risk_score"])}</p>
    <p><strong>Overall Risk Level:</strong> {esc(report["summary"]["overall_risk_level"])}</p>

    <h2>Findings</h2>
    <table>
      <tr>
        <th>Name</th>
        <th>Resource Type</th>
        <th>Resource ID</th>
        <th>Severity</th>
        <th>Details</th>
        <th>Recommendation</th>
        <th>Status</th>
      </tr>
      {rows}
    </table>
  </div>
</body>
</html>
"""

    output_file.write_text(content, encoding="utf-8")


def write_reports(report: dict, output_dir: Path, output_format: str) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    if output_format in ["all", "csv"]:
        write_csv_report(report, output_dir)

    if output_format in ["all", "json"]:
        write_json_report(report, output_dir)
        write_findings_json(report["findings"], output_dir)

    if output_format in ["all", "ndjson"]:
        write_ndjson_events(report, output_dir)

    if output_format in ["all", "txt"]:
        write_txt_summary(report, output_dir)

    if output_format in ["all", "html"]:
        write_html_report(report, output_dir)


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Static cloud security misconfiguration checker for demo AWS-style JSON configs."
    )

    parser.add_argument(
        "--input",
        default="sample_configs",
        help="Input directory containing cloud config JSON files.",
    )

    parser.add_argument(
        "--output",
        default="reports",
        help="Output directory.",
    )

    parser.add_argument(
        "--format",
        choices=["all", "csv", "txt", "json", "ndjson", "html"],
        default="all",
        help="Output format.",
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    input_dir = Path(args.input)
    output_dir = Path(args.output)

    configs = load_configs(input_dir)
    findings = []

    for config in configs:
        findings.extend(check_config(config))

    report = build_report(configs, findings)
    write_reports(report, output_dir, args.format)

    print("Cloud security misconfiguration check completed.")
    print(f"Configs checked: {report['summary']['total_configs']}")
    print(f"Findings: {report['summary']['total_findings']}")
    print(f"Overall risk level: {report['summary']['overall_risk_level']}")
    print(f"Output directory: {output_dir}")


if __name__ == "__main__":
    main()
