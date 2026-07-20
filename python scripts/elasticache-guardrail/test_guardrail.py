import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


MODULE_PATH = Path(__file__).with_name("guardrail.py")
SPEC = importlib.util.spec_from_file_location("elasticache_guardrail", MODULE_PATH)
guardrail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guardrail)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.deleted = []

    def _describe(self, key):
        item = self.responses.pop(0)
        return {key: [] if item is None else [item]}

    def describe_cache_clusters(self, **kwargs):
        return self._describe("CacheClusters")

    def describe_replication_groups(self, **kwargs):
        return self._describe("ReplicationGroups")

    def describe_serverless_caches(self, **kwargs):
        return self._describe("ServerlessCaches")

    def delete_cache_cluster(self, **kwargs):
        self.deleted.append(("cluster", kwargs))
        return {"CacheCluster": {"CacheClusterStatus": "deleting"}}

    def delete_replication_group(self, **kwargs):
        self.deleted.append(("replication", kwargs))
        return {"ReplicationGroup": {"Status": "deleting"}}

    def delete_serverless_cache(self, **kwargs):
        self.deleted.append(("serverless", kwargs))
        return {"ServerlessCache": {"Status": "deleting"}}


class EventTests(unittest.TestCase):
    def test_parses_cloudtrail_replication_group_creation(self):
        event = {
            "region": "us-east-1",
            "detail": {
                "eventSource": "elasticache.amazonaws.com",
                "eventName": "CreateReplicationGroup",
                "awsRegion": "us-west-2",
                "requestParameters": {"replicationGroupId": "redis-group"},
            },
        }
        self.assertEqual(guardrail.event_targets(event), [{
            "region": "us-west-2",
            "resource_type": "ReplicationGroup",
            "identifier": "redis-group",
        }])

    def test_parses_native_serverless_created_event(self):
        event = {
            "source": "aws.elasticache",
            "detail-type": "Cache Created",
            "region": "us-east-1",
            "resources": [
                "arn:aws:elasticache:us-east-1:123456789012:serverlesscache:cache-a"
            ],
            "detail": {},
        }
        self.assertEqual(
            guardrail.event_targets(event)[0]["resource_type"], "ServerlessCache"
        )

    def test_ignores_unrelated_event(self):
        event = {"detail": {
            "eventSource": "elasticache.amazonaws.com",
            "eventName": "ModifyReplicationGroup",
        }}
        self.assertEqual(guardrail.event_targets(event), [])


class DeletionTests(unittest.TestCase):
    def target(self, resource_type="ReplicationGroup"):
        return {
            "region": "us-east-1",
            "resource_type": resource_type,
            "identifier": "cache-a",
        }

    def test_waits_for_available_then_deletes_redis_group(self):
        client = FakeClient([
            {"Status": "creating", "Engine": "redis"},
            {"Status": "available", "Engine": "redis"},
        ])
        with patch.object(guardrail.time, "sleep"):
            action = guardrail.delete_target(
                client, self.target(), guardrail.time.monotonic() + 30, 1
            )
        self.assertEqual(action["status"], "DELETE_REQUESTED")
        self.assertEqual(action["status_checks"], 2)
        self.assertEqual(client.deleted[0][1]["RetainPrimaryCluster"], False)

    def test_ignores_valkey(self):
        client = FakeClient([{"Status": "available", "Engine": "valkey"}])
        action = guardrail.delete_target(
            client, self.target(), guardrail.time.monotonic() + 30, 1
        )
        self.assertEqual(action["status"], "IGNORED_NON_REDIS")
        self.assertEqual(client.deleted, [])

    def test_stops_when_already_deleting(self):
        client = FakeClient([{"Status": "deleting", "Engine": "redis"}])
        action = guardrail.delete_target(
            client, self.target(), guardrail.time.monotonic() + 30, 1
        )
        self.assertEqual(action["status"], "DELETE_IN_PROGRESS")
        self.assertEqual(client.deleted, [])

    def test_stops_when_resource_is_gone(self):
        client = FakeClient([None])
        action = guardrail.delete_target(
            client, self.target(), guardrail.time.monotonic() + 30, 1
        )
        self.assertEqual(action["status"], "ALREADY_DELETED")

    def test_does_not_delete_replication_group_member_as_standalone(self):
        client = FakeClient([{
            "CacheClusterStatus": "available",
            "Engine": "redis",
            "ReplicationGroupId": "existing-group",
        }])
        action = guardrail.delete_target(
            client,
            self.target("CacheCluster"),
            guardrail.time.monotonic() + 30,
            1,
        )
        self.assertEqual(action["status"], "IGNORED_REPLICATION_GROUP_MEMBER")
        self.assertEqual(client.deleted, [])

    def test_deletes_redis_serverless_without_final_snapshot(self):
        client = FakeClient([{"Status": "available", "Engine": "redis"}])
        action = guardrail.delete_target(
            client,
            self.target("ServerlessCache"),
            guardrail.time.monotonic() + 30,
            1,
        )
        self.assertTrue(action["delete_requested"])
        self.assertEqual(
            client.deleted[0],
            ("serverless", {"ServerlessCacheName": "cache-a"}),
        )


if __name__ == "__main__":
    unittest.main()
