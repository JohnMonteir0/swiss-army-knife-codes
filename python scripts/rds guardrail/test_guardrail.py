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


if __name__ == "__main__":
    unittest.main()
