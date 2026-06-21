import unittest
from pathlib import Path
import sys


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from src.cloud_config_checker import check_s3_bucket
from src.cloud_config_checker import check_security_group
from src.cloud_config_checker import check_iam_policy
from src.cloud_config_checker import check_rds_instance
from src.cloud_config_checker import calculate_risk_score
from src.cloud_config_checker import calculate_overall_risk_level


class TestCloudDetectionLogic(unittest.TestCase):
    def test_public_s3_bucket_detection(self):
        config = {
            "resource_type": "aws_s3_bucket",
            "resource_id": "demo-public-bucket",
            "public_access": True,
            "encryption_enabled": True,
            "logging_enabled": True,
            "versioning_enabled": True,
        }

        findings = check_s3_bucket(config)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "S3 Bucket Allows Public Access")
        self.assertEqual(findings[0]["severity"], "High")

    def test_security_group_open_ssh_detection(self):
        config = {
            "resource_type": "aws_security_group",
            "resource_id": "demo-sg",
            "rules": [
                {
                    "protocol": "tcp",
                    "port": 22,
                    "cidr": "0.0.0.0/0",
                }
            ],
        }

        findings = check_security_group(config)

        self.assertEqual(len(findings), 1)
        self.assertIn("SSH", findings[0]["name"])
        self.assertEqual(findings[0]["severity"], "High")

    def test_iam_admin_policy_detection(self):
        config = {
            "resource_type": "aws_iam_policy",
            "resource_id": "demo-admin-policy",
            "statements": [
                {
                    "effect": "Allow",
                    "actions": ["*"],
                    "resources": ["*"],
                }
            ],
        }

        findings = check_iam_policy(config)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "Critical")

    def test_public_rds_detection(self):
        config = {
            "resource_type": "aws_rds_instance",
            "resource_id": "demo-db",
            "publicly_accessible": True,
            "encryption_enabled": True,
            "backup_enabled": True,
            "deletion_protection": True,
        }

        findings = check_rds_instance(config)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["name"], "Database Instance Publicly Accessible")
        self.assertEqual(findings[0]["severity"], "High")

    def test_risk_score(self):
        findings = [
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "Medium"},
        ]

        self.assertEqual(calculate_risk_score(findings), 30)
        self.assertEqual(calculate_overall_risk_level(30), "Critical")


if __name__ == "__main__":
    unittest.main()
