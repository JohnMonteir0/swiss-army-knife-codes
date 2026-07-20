#!/usr/bin/env python3
"""Delete newly created Redis OSS ElastiCache resources.

Designed for an EventBridge-triggered AWS Lambda.  The handler accepts
CloudTrail events for CreateCacheCluster, CreateReplicationGroup, and
CreateServerlessCache, as well as ElastiCache's direct ``Cache Created`` event.

Only resources whose API-reported Engine is exactly ``redis`` are deleted.
Valkey and Memcached are always ignored.

Lambda entry point: guardrail.lambda_handler
"""

import json
import time

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ModuleNotFoundError as error:
    if error.name not in {"boto3", "botocore"}:
        raise
    boto3 = None
    BotoCoreError = ClientError = Exception
    IMPORT_ERROR = error
else:
    IMPORT_ERROR = None


ELASTICACHE_EVENT_SOURCE = "elasticache.amazonaws.com"
ELASTICACHE_EVENTBRIDGE_SOURCE = "aws.elasticache"
DEFAULT_RETRY_DELAY_SECONDS = 15
DEFAULT_LOCAL_WAIT_SECONDS = 840
LAMBDA_TIMEOUT_BUFFER_SECONDS = 20

CREATION_EVENTS = {
    "CreateCacheCluster": "CacheCluster",
    "CreateReplicationGroup": "ReplicationGroup",
    "CreateServerlessCache": "ServerlessCache",
}

IDENTIFIER_KEYS = {
    "CacheCluster": {"CacheClusterId", "cacheClusterId"},
    "ReplicationGroup": {"ReplicationGroupId", "replicationGroupId"},
    "ServerlessCache": {"ServerlessCacheName", "serverlessCacheName"},
}

RESOURCES = {
    "CacheCluster": {
        "describe_api": "describe_cache_clusters",
        "result_key": "CacheClusters",
        "id_arg": "CacheClusterId",
        "id_key": "CacheClusterId",
        "status_key": "CacheClusterStatus",
        "delete_api": "delete_cache_cluster",
        "delete_args": lambda identifier: {"CacheClusterId": identifier},
        "not_found": {"CacheClusterNotFound", "CacheClusterNotFoundFault"},
    },
    "ReplicationGroup": {
        "describe_api": "describe_replication_groups",
        "result_key": "ReplicationGroups",
        "id_arg": "ReplicationGroupId",
        "id_key": "ReplicationGroupId",
        "status_key": "Status",
        "delete_api": "delete_replication_group",
        "delete_args": lambda identifier: {
            "ReplicationGroupId": identifier,
            "RetainPrimaryCluster": False,
        },
        "not_found": {
            "ReplicationGroupNotFoundFault",
            "ReplicationGroupNotFound",
        },
    },
    "ServerlessCache": {
        "describe_api": "describe_serverless_caches",
        "result_key": "ServerlessCaches",
        "id_arg": "ServerlessCacheName",
        "id_key": "ServerlessCacheName",
        "status_key": "Status",
        "delete_api": "delete_serverless_cache",
        "delete_args": lambda identifier: {"ServerlessCacheName": identifier},
        "not_found": {
            "ServerlessCacheNotFoundFault",
            "ServerlessCacheNotFound",
        },
    },
}


class ElastiCacheStatusTimeoutError(RuntimeError):
    """Raised when a cache does not become deletable in the Lambda budget."""


def response(result):
    print(json.dumps(result, default=str))
    return result


def find_nested_value(data, candidate_keys):
    """Find the first non-empty identifier in a CloudTrail payload."""
    if isinstance(data, dict):
        for key in candidate_keys:
            if data.get(key):
                return data[key]
        for value in data.values():
            found = find_nested_value(value, candidate_keys)
            if found:
                return found
    elif isinstance(data, list):
        for value in data:
            found = find_nested_value(value, candidate_keys)
            if found:
                return found
    return None


def normalize_target(target):
    if not isinstance(target, dict):
        return None
    resource_type = target.get("resource_type") or target.get("resourceType")
    region = target.get("region")
    identifier = target.get("identifier")
    if resource_type not in RESOURCES or not region or not identifier:
        return None
    return {
        "region": str(region),
        "resource_type": resource_type,
        "identifier": str(identifier),
    }


def target_from_arn(arn, region=None):
    """Convert an ElastiCache cluster/replication-group/serverless ARN."""
    if not isinstance(arn, str):
        return None
    parts = arn.split(":", 6)
    if len(parts) != 7 or parts[2] != "elasticache":
        return None
    arn_region, resource_kind, identifier = parts[3], parts[5], parts[6]
    resource_type = {
        "cluster": "CacheCluster",
        "replicationgroup": "ReplicationGroup",
        "serverlesscache": "ServerlessCache",
    }.get(resource_kind.lower())
    return normalize_target({
        "region": region or arn_region,
        "resource_type": resource_type,
        "identifier": identifier,
    })


def eventbridge_target(event):
    detail = event.get("detail") if isinstance(event, dict) else None
    if not isinstance(detail, dict):
        return None

    # CloudTrail API event. Failed create calls do not create a resource.
    if detail.get("eventSource") == ELASTICACHE_EVENT_SOURCE:
        if detail.get("errorCode"):
            return None
        resource_type = CREATION_EVENTS.get(detail.get("eventName"))
        if not resource_type:
            return None
        identifier = find_nested_value(
            [detail.get("responseElements"), detail.get("requestParameters")],
            IDENTIFIER_KEYS[resource_type],
        )
        return normalize_target({
            "region": detail.get("awsRegion") or event.get("region"),
            "resource_type": resource_type,
            "identifier": identifier,
        })

    # Native ElastiCache event. The resource ARN identifies the cache type.
    if (
        event.get("source") == ELASTICACHE_EVENTBRIDGE_SOURCE
        and str(event.get("detail-type", "")).lower() == "cache created"
    ):
        for arn in event.get("resources", []):
            target = target_from_arn(arn, event.get("region"))
            if target:
                return target
    return None


def event_targets(event):
    """Parse explicit test input or one supported EventBridge event."""
    if not isinstance(event, dict):
        return []
    raw_targets = event.get("targets")
    if isinstance(raw_targets, dict):
        raw_targets = [raw_targets]
    elif not isinstance(raw_targets, list):
        raw_targets = [event.get("target", event)]

    targets = [target for raw in raw_targets if (target := normalize_target(raw))]
    event_target = eventbridge_target(event)
    if event_target:
        targets.append(event_target)

    unique = []
    seen = set()
    for target in targets:
        key = (target["region"], target["resource_type"], target["identifier"])
        if key not in seen:
            seen.add(key)
            unique.append(target)
    return unique


def error_code(error):
    return error.response.get("Error", {}).get("Code", "")


def describe_resource(client, resource_type, identifier):
    resource = RESOURCES[resource_type]
    try:
        result = getattr(client, resource["describe_api"])(
            **{resource["id_arg"]: identifier}
        )
    except ClientError as error:
        if error_code(error) in resource["not_found"]:
            return None
        raise
    items = result.get(resource["result_key"], [])
    return items[0] if items else None


def wait_until_deletable(client, target, deadline, retry_delay_seconds):
    """Wait for available; return immediately when deleting or gone."""
    resource_type = target["resource_type"]
    resource = RESOURCES[resource_type]
    identifier = target["identifier"]
    retry_delay_seconds = max(float(retry_delay_seconds), 0.1)
    checks = 0
    last_status = "unknown"

    while True:
        checks += 1
        item = describe_resource(client, resource_type, identifier)
        if item is None:
            return None, "deleted", checks
        last_status = str(item.get(resource["status_key"], "unknown")).lower()
        if last_status in {"deleting", "deleted"}:
            return item, last_status, checks
        if last_status == "available":
            return item, last_status, checks

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ElastiCacheStatusTimeoutError(
                f"{resource_type} {identifier} did not become available before "
                f"the Lambda time budget expired; last status: {last_status}; "
                f"status checks: {checks}."
            )
        time.sleep(min(retry_delay_seconds, remaining))


def delete_target(client, target, deadline, retry_delay_seconds):
    resource_type = target["resource_type"]
    identifier = target["identifier"]
    resource = RESOURCES[resource_type]
    item, status, checks = wait_until_deletable(
        client, target, deadline, retry_delay_seconds
    )
    action = {
        **target,
        "engine": None if item is None else item.get("Engine"),
        "status_checks": checks,
        "observed_status": status,
        "delete_requested": False,
    }

    if item is None:
        action["status"] = "ALREADY_DELETED"
        return action
    if status in {"deleting", "deleted"}:
        action["status"] = "DELETE_IN_PROGRESS"
        return action

    engine = str(item.get("Engine", "")).lower()
    if engine != "redis":
        action["status"] = "IGNORED_NON_REDIS"
        action["ignore_reason"] = (
            f"Engine is {engine or 'unknown'}, not redis. Valkey and Memcached "
            "are outside this guardrail."
        )
        return action

    # A CacheCluster inside a replication group is not a standalone cache and
    # DeleteCacheCluster is invalid for several member configurations. The
    # CreateReplicationGroup event is responsible for a newly-created group.
    if resource_type == "CacheCluster" and item.get("ReplicationGroupId"):
        action["status"] = "IGNORED_REPLICATION_GROUP_MEMBER"
        action["ignore_reason"] = (
            "CacheCluster belongs to replication group "
            f"{item['ReplicationGroupId']}; refusing to delete an individual member."
        )
        return action

    try:
        result = getattr(client, resource["delete_api"])(
            **resource["delete_args"](identifier)
        )
    except ClientError as error:
        if error_code(error) in resource["not_found"]:
            action["status"] = "ALREADY_DELETED"
            action["observed_status"] = "deleted"
            return action
        raise

    deleted_item = result.get(resource["result_key"][:-1], {})
    delete_status = str(
        deleted_item.get(resource["status_key"], "deleting")
    ).lower()
    action["delete_requested"] = True
    action["observed_status"] = delete_status
    action["status"] = "DELETE_REQUESTED"
    return action


def lambda_deadline(event, context):
    """Reserve a small response buffer and use the rest of the Lambda runtime."""
    if context and hasattr(context, "get_remaining_time_in_millis"):
        usable_seconds = max(
            context.get_remaining_time_in_millis() / 1000
            - LAMBDA_TIMEOUT_BUFFER_SECONDS,
            0,
        )
    else:
        usable_seconds = max(
            float(event.get("status_wait_timeout_seconds", DEFAULT_LOCAL_WAIT_SECONDS)),
            0,
        )
    # Tests/operators may choose a smaller cap, but never exceed Lambda time.
    if "status_wait_timeout_seconds" in event and context:
        usable_seconds = min(
            usable_seconds, max(float(event["status_wait_timeout_seconds"]), 0)
        )
    return time.monotonic() + usable_seconds, usable_seconds


def lambda_handler(event, context):
    event = event or {}
    if IMPORT_ERROR is not None:
        raise RuntimeError(f"Missing required Python package: {IMPORT_ERROR.name}")

    targets = event_targets(event)
    if not targets:
        return response({
            "status": "PASS",
            "event_ignored": True,
            "ignore_reason": (
                "No supported ElastiCache creation target was found. Only "
                "CreateCacheCluster, CreateReplicationGroup, "
                "CreateServerlessCache, and Cache Created events are handled."
            ),
            "target_count": 0,
            "actions": [],
            "errors": [],
        })

    deadline, usable_seconds = lambda_deadline(event, context)
    retry_delay = event.get(
        "status_retry_delay_seconds", DEFAULT_RETRY_DELAY_SECONDS
    )
    session = boto3.Session()
    clients = {}
    actions = []
    errors = []

    for target in targets:
        region = target["region"]
        try:
            if region not in clients:
                clients[region] = session.client("elasticache", region_name=region)
            actions.append(delete_target(
                clients[region], target, deadline, retry_delay
            ))
        except (BotoCoreError, ClientError, ElastiCacheStatusTimeoutError) as error:
            errors.append({**target, "error": str(error)})
        # Do not begin another target when only the response buffer remains.
        if time.monotonic() >= deadline:
            break

    status = "ERROR" if errors else (
        "DELETE_REQUESTED"
        if any(action["delete_requested"] for action in actions)
        else "PASS"
    )
    return response({
        "status": status,
        "event_ignored": False,
        "target_count": len(targets),
        "targets": targets,
        "action_count": len(actions),
        "actions": actions,
        "lambda_wait_budget_seconds": usable_seconds,
        "errors": errors,
    })
