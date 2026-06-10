import importlib.util
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("guardrail.py")
SPEC = importlib.util.spec_from_file_location("guardrail", MODULE_PATH)
guardrail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardrail)


class PolicyExceptionTests(unittest.TestCase):
    def setUp(self):
        self.original_exceptions = {
            resource_type: set(identifiers)
            for resource_type, identifiers in guardrail.POLICY_EXCEPTIONS.items()
        }

    def tearDown(self):
        guardrail.POLICY_EXCEPTIONS.clear()
        guardrail.POLICY_EXCEPTIONS.update(self.original_exceptions)

    def test_outdated_instance_is_ignored_when_identifier_is_excepted(self):
        guardrail.POLICY_EXCEPTIONS["DBInstance"] = {"Legacy-Instance"}
        resource = guardrail.resource_by_type("DBInstance")
        item = {
            "DBInstanceIdentifier": "legacy-instance",
            "DBInstanceStatus": "available",
            "Engine": "mysql",
            "EngineVersion": "5.7.44",
        }

        self.assertIsNone(guardrail.finding_from_item("us-east-1", resource, item))

    def test_outdated_cluster_is_ignored_when_identifier_is_excepted(self):
        guardrail.POLICY_EXCEPTIONS["DBCluster"] = {"legacy-cluster"}
        resource = guardrail.resource_by_type("DBCluster")
        item = {
            "DBClusterIdentifier": "legacy-cluster",
            "Status": "available",
            "Engine": "aurora-mysql",
            "EngineVersion": "8.0.mysql_aurora.3.08.2",
        }

        self.assertIsNone(guardrail.finding_from_item("us-east-1", resource, item))

    def test_exception_applies_only_to_matching_resource_type(self):
        guardrail.POLICY_EXCEPTIONS["DBCluster"] = {"shared-identifier"}
        resource = guardrail.resource_by_type("DBInstance")
        item = {
            "DBInstanceIdentifier": "shared-identifier",
            "DBInstanceStatus": "available",
            "Engine": "postgres",
            "EngineVersion": "16.4",
        }

        finding = guardrail.finding_from_item("us-east-1", resource, item)

        self.assertIsNotNone(finding)
        self.assertEqual(finding["identifier"], "shared-identifier")

    def test_account_specific_exception_matches_identifier_and_account(self):
        guardrail.POLICY_EXCEPTIONS["DBInstance"] = {
            ("123456789012", "shared-instance")
        }
        resource = guardrail.resource_by_type("DBInstance")
        item = {
            "DBInstanceIdentifier": "shared-instance",
            "DBInstanceArn": (
                "arn:aws:rds:us-east-1:123456789012:db:shared-instance"
            ),
            "DBInstanceStatus": "available",
            "Engine": "mysql",
            "EngineVersion": "5.7.44",
        }

        exception = guardrail.policy_exception_from_item(
            "us-east-1", resource, item
        )

        self.assertIsNone(guardrail.finding_from_item("us-east-1", resource, item))
        self.assertEqual(exception["account_id"], "123456789012")
        self.assertEqual(exception["result"], "EXCEPTION")

    def test_account_specific_exception_does_not_match_another_account(self):
        guardrail.POLICY_EXCEPTIONS["DBCluster"] = {
            ("123456789012", "shared-cluster")
        }
        resource = guardrail.resource_by_type("DBCluster")
        item = {
            "DBClusterIdentifier": "shared-cluster",
            "DBClusterArn": (
                "arn:aws:rds:us-east-1:999999999999:cluster:shared-cluster"
            ),
            "Status": "available",
            "Engine": "aurora-mysql",
            "EngineVersion": "8.0.mysql_aurora.3.08.2",
        }

        finding = guardrail.finding_from_item("us-east-1", resource, item)

        self.assertIsNotNone(finding)
        self.assertIsNone(
            guardrail.policy_exception_from_item("us-east-1", resource, item)
        )

    def test_compliant_resource_is_not_reported_as_an_exception(self):
        guardrail.POLICY_EXCEPTIONS["DBInstance"] = {"current-instance"}
        resource = guardrail.resource_by_type("DBInstance")
        item = {
            "DBInstanceIdentifier": "current-instance",
            "DBInstanceStatus": "available",
            "Engine": "mysql",
            "EngineVersion": "8.4.7",
        }

        self.assertIsNone(
            guardrail.policy_exception_from_item("us-east-1", resource, item)
        )


if __name__ == "__main__":
    unittest.main()
