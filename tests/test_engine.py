import unittest
import engine
from cli_parser import parse_command


class TestEngineMissingFlag(unittest.TestCase):

    def setUp(self):
        engine._rules_cache.clear()

    def _messages(self, cmd):
        return [f["message"] for f in engine.analyze(parse_command(cmd))]

    def test_imdsv2_fires_when_absent(self):
        self.assertTrue(any("IMDSv2" in m for m in self._messages(
            "aws ec2 run-instances --image-id ami-12345"
        )))

    def test_imdsv2_no_finding_when_correct(self):
        self.assertFalse(any("IMDSv2" in m for m in self._messages(
            "aws ec2 run-instances --image-id ami-12345 --metadata-options HttpTokens=required"
        )))

    def test_imdsv2_fires_when_wrong_value(self):
        self.assertTrue(any("IMDSv2" in m for m in self._messages(
            "aws ec2 run-instances --image-id ami-12345 --metadata-options HttpTokens=optional"
        )))

    def test_rds_encryption_fires_when_absent(self):
        self.assertTrue(any("encryption" in m.lower() for m in self._messages(
            "aws rds create-db-instance --db-instance-identifier prod --engine mysql"
        )))

    def test_rds_encryption_no_finding_when_present(self):
        self.assertFalse(any("RDS storage encryption" in m for m in self._messages(
            "aws rds create-db-instance --db-instance-identifier prod "
            "--engine mysql --storage-encrypted"
        )))

    def test_cloudtrail_multiregion_fires_when_absent(self):
        self.assertTrue(any("multi-region" in m.lower() for m in self._messages(
            "aws cloudtrail create-trail --name my-trail --s3-bucket-name my-bucket"
        )))

    def test_cloudtrail_multiregion_no_finding_when_present(self):
        self.assertFalse(any("multi-region" in m.lower() for m in self._messages(
            "aws cloudtrail create-trail --name my-trail "
            "--s3-bucket-name my-bucket --is-multi-region-trail"
        )))

    def test_sts_mfa_fires_when_absent(self):
        self.assertTrue(any("MFA" in m for m in self._messages(
            "aws sts get-session-token"
        )))

    def test_sts_mfa_no_finding_when_present(self):
        self.assertFalse(any("MFA" in m for m in self._messages(
            "aws sts get-session-token --serial-number arn:aws:iam::123:mfa/device --token-code 123456"
        )))

    def test_s3_object_lock_fires_when_absent(self):
        self.assertTrue(any("Object Lock" in m for m in self._messages(
            "aws s3api create-bucket --bucket my-bucket"
        )))

    def test_s3_object_lock_no_finding_when_present(self):
        self.assertFalse(any("Object Lock" in m for m in self._messages(
            "aws s3api create-bucket --bucket my-bucket --object-lock-enabled-for-bucket"
        )))


class TestEngineForbiddenValue(unittest.TestCase):

    def setUp(self):
        engine._rules_cache.clear()

    def _findings(self, cmd):
        return engine.analyze(parse_command(cmd))

    def _messages(self, cmd):
        return [f["message"] for f in self._findings(cmd)]

    def test_s3_public_read_acl_fires(self):
        findings = self._findings("aws s3 cp data.csv s3://bucket/ --acl public-read")
        self.assertTrue(any(f["severity"] == "HIGH" for f in findings))
        self.assertTrue(any("public-read" in m.lower() for m in [f["message"] for f in findings]))

    def test_s3_private_acl_no_finding(self):
        self.assertFalse(any("public-read" in m.lower() for m in self._messages(
            "aws s3 cp data.csv s3://bucket/ --acl private"
        )))

    def test_administrator_access_policy_fires(self):
        findings = self._findings(
            "aws iam attach-role-policy --role-name my-role "
            "--policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
        )
        self.assertTrue(any(f["severity"] == "HIGH" for f in findings))
        self.assertTrue(any("AdministratorAccess" in f["message"] for f in findings))

    def test_power_user_access_policy_fires(self):
        self.assertTrue(any("PowerUserAccess" in m for m in self._messages(
            "aws iam attach-role-policy --role-name my-role "
            "--policy-arn arn:aws:iam::aws:policy/PowerUserAccess"
        )))

    def test_rds_publicly_accessible_fires(self):
        self.assertTrue(any("publicly accessible" in m.lower() for m in self._messages(
            "aws rds create-db-instance --db-instance-identifier prod "
            "--engine mysql --publicly-accessible"
        )))

    def test_rds_no_publicly_accessible_no_finding(self):
        self.assertFalse(any("publicly accessible" in m.lower() for m in self._messages(
            "aws rds create-db-instance --db-instance-identifier prod "
            "--engine mysql --no-publicly-accessible"
        )))

    def test_sg_open_cidr_fires(self):
        findings = self._findings(
            "aws ec2 authorize-security-group-ingress --group-id sg-123 "
            "--protocol tcp --port 22 --cidr 0.0.0.0/0"
        )
        self.assertTrue(any(f["severity"] == "HIGH" for f in findings))

    def test_associate_public_ip_fires(self):
        self.assertTrue(any("public IP" in m for m in self._messages(
            "aws ec2 run-instances --image-id ami-12345 --associate-public-ip-address"
        )))

    def test_no_associate_public_ip_no_finding(self):
        self.assertFalse(any("public IP" in m for m in self._messages(
            "aws ec2 run-instances --image-id ami-12345 --no-associate-public-ip-address"
        )))

    def test_no_include_global_service_events_fires(self):
        self.assertTrue(any("global service" in m.lower() for m in self._messages(
            "aws cloudtrail create-trail --name my-trail "
            "--s3-bucket-name my-bucket --no-include-global-service-events"
        )))


class TestEngineAlwaysWarn(unittest.TestCase):

    def setUp(self):
        engine._rules_cache.clear()

    def _findings(self, cmd):
        return engine.analyze(parse_command(cmd))

    def test_cloudtrail_stop_logging_fires(self):
        findings = self._findings("aws cloudtrail stop-logging --name my-trail")
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f["severity"] == "HIGH" for f in findings))

    def test_kms_schedule_deletion_fires(self):
        self.assertGreater(len(self._findings("aws kms schedule-key-deletion --key-id key-123")), 0)

    def test_sts_assume_role_fires(self):
        findings = self._findings(
            "aws sts assume-role --role-arn arn:aws:iam::123456789012:role/MyRole "
            "--role-session-name session1"
        )
        self.assertGreater(len(findings), 0)
        self.assertTrue(any(f["severity"] == "HIGH" for f in findings))

    def test_s3api_create_bucket_always_warns(self):
        findings = self._findings("aws s3api create-bucket --bucket my-bucket")
        self.assertGreater(len(findings), 0)

    def test_iam_create_access_key_fires(self):
        findings = self._findings("aws iam create-access-key --user-name myuser")
        self.assertTrue(any(f["severity"] == "HIGH" for f in findings))


class TestEngineGeneral(unittest.TestCase):

    def setUp(self):
        engine._rules_cache.clear()

    def test_unknown_command_no_findings(self):
        findings = engine.analyze(parse_command("aws s3 ls"))
        self.assertEqual(findings, [])

    def test_all_findings_have_required_fields(self):
        parsed = parse_command("aws ec2 run-instances --image-id ami-12345")
        for f in engine.analyze(parsed):
            self.assertIn("severity", f)
            self.assertIn("message", f)
            self.assertIn("context", f)
            self.assertIn("suggestion", f)

    def test_all_severities_are_valid(self):
        parsed = parse_command("aws ec2 run-instances --image-id ami-12345")
        valid = {"HIGH", "MEDIUM", "LOW", "INFO"}
        for f in engine.analyze(parsed):
            self.assertIn(f["severity"], valid)

    def test_rules_load_without_errors(self):
        engine._rules_cache.clear()
        rules = engine._load_rules()
        self.assertGreater(len(rules), 0)

    def test_rules_load_expected_command_count(self):
        engine._rules_cache.clear()
        rules = engine._load_rules()
        self.assertGreaterEqual(len(rules), 369)


if __name__ == "__main__":
    unittest.main(verbosity=2)
