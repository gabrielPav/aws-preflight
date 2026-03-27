import unittest
from cli_parser import parse_command


class TestParser(unittest.TestCase):

    def test_basic_command(self):
        r = parse_command("aws s3 ls")
        self.assertIsNotNone(r)
        self.assertEqual(r["service"], "s3")
        self.assertEqual(r["operation"], "ls")
        self.assertEqual(r["flags"], {})

    def test_flag_with_space(self):
        r = parse_command("aws ec2 run-instances --image-id ami-12345")
        self.assertEqual(r["flags"]["--image-id"], "ami-12345")

    def test_flag_with_equals(self):
        r = parse_command("aws ec2 run-instances --metadata-options=HttpTokens=required")
        self.assertEqual(r["flags"]["--metadata-options"], "HttpTokens=required")

    def test_boolean_flag(self):
        r = parse_command("aws s3 sync src s3://bucket --delete")
        self.assertIs(r["flags"]["--delete"], True)

    def test_multiple_flags(self):
        r = parse_command(
            "aws rds create-db-instance --storage-encrypted "
            "--deletion-protection --backup-retention-period 7"
        )
        self.assertIs(r["flags"]["--storage-encrypted"], True)
        self.assertIs(r["flags"]["--deletion-protection"], True)
        self.assertEqual(r["flags"]["--backup-retention-period"], "7")

    def test_non_aws_command_returns_none(self):
        self.assertIsNone(parse_command("kubectl get pods"))
        self.assertIsNone(parse_command("terraform apply"))
        self.assertIsNone(parse_command(""))

    def test_too_short_returns_none(self):
        self.assertIsNone(parse_command("aws"))
        self.assertIsNone(parse_command("aws s3"))

    def test_positional_args_not_in_flags(self):
        r = parse_command("aws s3 cp data.csv s3://bucket/")
        self.assertNotIn("data.csv", r["flags"])
        self.assertNotIn("s3://bucket/", r["flags"])

    def test_raw_preserved(self):
        cmd = "aws ec2 run-instances --image-id ami-12345"
        r = parse_command(cmd)
        self.assertEqual(r["raw"], cmd)

    def test_quoted_value(self):
        r = parse_command('aws ec2 run-instances --image-id ami-12345 --key-name "my key"')
        self.assertEqual(r["flags"]["--key-name"], "my key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
