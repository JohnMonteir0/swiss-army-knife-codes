import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("guardrail.py")
SPEC = importlib.util.spec_from_file_location("guardrail", MODULE_PATH)
guardrail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardrail)


class PolicyExceptionTests(unittest.TestCase):
    def setUp(self):
        self.original_policy = dict(guardrail.POLICY)
        self.original_exceptions = {
            resource_type: set(identifiers)
            for resource_type, identifiers in guardrail.POLICY_EXCEPTIONS.items()
        }
        guardrail.POLICY.clear()
        guardrail.POLICY.update({
            "mysql": {
                "minimum": (8, 4, 7),
                "required": "8.4.7",
                "message": "MySQL version is below 8.4.7",
            },
            "aurora-mysql": {
                "minimum": (3, 10, 3),
                "required": "8.0.mysql_aurora.3.10.3",
                "message": (
                    "Aurora MySQL version is below 8.0.mysql_aurora.3.10.3"
                ),
            },
            "postgres": {
                "minimum_major": 17,
                "required": "17",
                "message": "PostgreSQL major version is below 17",
            },
        })

    def tearDown(self):
        guardrail.POLICY.clear()
        guardrail.POLICY.update(self.original_policy)
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

    def test_cluster_member_inherits_parent_cluster_exception(self):
        guardrail.POLICY_EXCEPTIONS["DBCluster"] = {
            ("123456789012", "cluster-guardrail")
        }
        resource = guardrail.resource_by_type("DBInstance")
        item = {
            "DBInstanceIdentifier": "cluster-guardrail-instance-1",
            "DBInstanceArn": (
                "arn:aws:rds:us-east-1:123456789012:db:"
                "cluster-guardrail-instance-1"
            ),
            "DBClusterIdentifier": "cluster-guardrail",
            "DBInstanceStatus": "available",
            "Engine": "aurora-mysql",
            "EngineVersion": "8.0.mysql_aurora.3.08.2",
        }

        exception = guardrail.policy_exception_from_item(
            "us-east-1", resource, item
        )

        self.assertIsNone(guardrail.finding_from_item("us-east-1", resource, item))
        self.assertEqual(
            exception["exception_match"]["match_type"], "PARENT_CLUSTER"
        )
        self.assertEqual(
            exception["exception_match"]["identifier"], "cluster-guardrail"
        )

    def test_cluster_member_does_not_inherit_exception_from_another_account(self):
        guardrail.POLICY_EXCEPTIONS["DBCluster"] = {
            ("123456789012", "cluster-guardrail")
        }
        resource = guardrail.resource_by_type("DBInstance")
        item = {
            "DBInstanceIdentifier": "cluster-guardrail-instance-1",
            "DBInstanceArn": (
                "arn:aws:rds:us-east-1:999999999999:db:"
                "cluster-guardrail-instance-1"
            ),
            "DBClusterIdentifier": "cluster-guardrail",
            "DBInstanceStatus": "available",
            "Engine": "aurora-mysql",
            "EngineVersion": "8.0.mysql_aurora.3.08.2",
        }

        self.assertIsNotNone(
            guardrail.finding_from_item("us-east-1", resource, item)
        )

    def test_read_replica_inherits_source_instance_exception(self):
        guardrail.POLICY_EXCEPTIONS["DBInstance"] = {
            ("123456789012", "primary-guardrail")
        }
        resource = guardrail.resource_by_type("DBInstance")
        item = {
            "DBInstanceIdentifier": "primary-guardrail-replica",
            "DBInstanceArn": (
                "arn:aws:rds:us-west-2:123456789012:db:"
                "primary-guardrail-replica"
            ),
            "ReadReplicaSourceDBInstanceIdentifier": (
                "arn:aws:rds:us-east-1:123456789012:db:primary-guardrail"
            ),
            "DBInstanceStatus": "available",
            "Engine": "mysql",
            "EngineVersion": "5.7.44",
        }

        exception = guardrail.policy_exception_from_item(
            "us-west-2", resource, item
        )

        self.assertIsNone(guardrail.finding_from_item("us-west-2", resource, item))
        self.assertEqual(
            exception["exception_match"]["match_type"], "SOURCE_INSTANCE"
        )
        self.assertEqual(
            exception["exception_match"]["identifier"], "primary-guardrail"
        )


class PolicyConfigurationTests(unittest.TestCase):
    def test_normalizes_json_policy_and_exceptions(self):
        policy = guardrail.normalize_policy({
            "mysql": {
                "minimum": [8, 4, 7],
                "required": "8.4.7",
                "message": "MySQL version is below 8.4.7",
            },
            "postgres": {
                "minimum_major": 17,
                "required": "17",
                "message": "PostgreSQL major version is below 17",
            },
        })
        exceptions = guardrail.normalize_policy_exceptions({
            "DBInstance": [
                "global-instance",
                ["123456789012", "account-instance"],
            ],
            "DBCluster": [],
        })

        self.assertEqual(policy["mysql"]["minimum"], (8, 4, 7))
        self.assertIn("global-instance", exceptions["DBInstance"])
        self.assertIn(
            ("123456789012", "account-instance"),
            exceptions["DBInstance"],
        )

    def test_rejects_invalid_exception_entry(self):
        with self.assertRaises(guardrail.PolicyConfigurationError):
            guardrail.normalize_policy_exceptions({
                "DBInstance": [{"account_id": "123456789012"}]
            })

    def test_loads_both_policy_objects_from_s3(self):
        class Body:
            def __init__(self, value):
                self.value = value

            def read(self):
                return json.dumps(self.value).encode("utf-8")

        class S3:
            def __init__(self, objects):
                self.objects = objects
                self.requests = []

            def get_object(self, Bucket, Key):
                self.requests.append((Bucket, Key))
                return {"Body": Body(self.objects[Key])}

        class Session:
            def __init__(self, s3):
                self.s3 = s3

            def client(self, service_name, region_name=None):
                self.service_name = service_name
                self.region_name = region_name
                return self.s3

        s3 = S3({
            "policy.json": {
                "mysql": {
                    "minimum": [8, 4, 7],
                    "required": "8.4.7",
                    "message": "MySQL version is below 8.4.7",
                }
            },
            "exceptions.json": {
                "DBInstance": [["123456789012", "account-instance"]],
                "DBCluster": [],
            },
        })
        session = Session(s3)
        original_policy = dict(guardrail.POLICY)
        original_exceptions = {
            key: set(value)
            for key, value in guardrail.POLICY_EXCEPTIONS.items()
        }
        try:
            result = guardrail.load_policy_configuration(
                session,
                bucket="policy-bucket",
                policy_key="policy.json",
                policy_exceptions_key="exceptions.json",
                bucket_region="us-east-1",
            )

            self.assertEqual(session.service_name, "s3")
            self.assertEqual(session.region_name, "us-east-1")
            self.assertEqual(s3.requests, [
                ("policy-bucket", "policy.json"),
                ("policy-bucket", "exceptions.json"),
            ])
            self.assertEqual(guardrail.POLICY["mysql"]["minimum"], (8, 4, 7))
            self.assertIn(
                ("123456789012", "account-instance"),
                guardrail.POLICY_EXCEPTIONS["DBInstance"],
            )
            self.assertFalse(result["assumed_role"])
        finally:
            guardrail.POLICY.clear()
            guardrail.POLICY.update(original_policy)
            guardrail.POLICY_EXCEPTIONS.clear()
            guardrail.POLICY_EXCEPTIONS.update(original_exceptions)

    def test_loads_policy_location_from_environment_variables(self):
        class Session:
            def client(self, service_name, region_name=None):
                self.service_name = service_name
                self.region_name = region_name
                return object()

        session = Session()
        policy = {
            "mysql": {
                "minimum": [8, 4, 7],
                "required": "8.4.7",
                "message": "MySQL version is below 8.4.7",
            }
        }
        exceptions = {"DBInstance": [], "DBCluster": []}
        with patch.dict(os.environ, {
            "POLICY_BUCKET": "policy-bucket",
            "POLICY_KEY": "policy.json",
            "POLICY_EXCEPTIONS_KEY": "policy-exceptions.json",
            "POLICY_BUCKET_REGION": "us-east-1",
        }, clear=True), patch.object(
            guardrail,
            "read_s3_json",
            side_effect=[policy, exceptions],
        ) as read_s3_json:
            result = guardrail.load_policy_configuration(session)

        self.assertEqual(session.service_name, "s3")
        self.assertEqual(session.region_name, "us-east-1")
        self.assertEqual(read_s3_json.call_args_list[0].args[1:], (
            "policy-bucket",
            "policy.json",
        ))
        self.assertEqual(read_s3_json.call_args_list[1].args[1:], (
            "policy-bucket",
            "policy-exceptions.json",
        ))
        self.assertEqual(result["bucket"], "policy-bucket")

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
