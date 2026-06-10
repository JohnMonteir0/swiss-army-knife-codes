#!/usr/bin/env python3
"""
RDS version guardrail.

Finds RDS and Aurora resources running below these approved versions:
  - MySQL: 8.4.7
  - Aurora MySQL: 8.0.mysql_aurora.3.10.3
  - PostgreSQL: major version 17

Works in two places:
  - Local CLI
  - AWS Lambda handler: guardrail.lambda_handler

Requires:
  pip install boto3

Examples:
  python guardrail.py
  python guardrail.py --profile my-profile
  python guardrail.py --regions us-east-1 us-west-2 --json
  python guardrail.py --delete-outdated

Lambda event example:
  {"regions": ["us-east-1", "us-west-2"]}
  {"regions": ["us-east-1"], "status_wait_timeout_seconds": 840}
  {"targets": [{"region": "us-east-1", "resource_type": "DBInstance", "identifier": "test-db"}]}
"""

import argparse
import json
import os
import re
import sys
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


# Loaded from S3 before a scan. Keeping these as module-level values avoids
# threading configuration through every policy evaluation and deletion path.
POLICY = {}
POLICY_EXCEPTIONS = {"DBInstance": set(), "DBCluster": set()}

POLICY_BUCKET_ENV = "POLICY_BUCKET"
POLICY_KEY_ENV = "POLICY_KEY"
POLICY_EXCEPTIONS_KEY_ENV = "POLICY_EXCEPTIONS_KEY"
POLICY_BUCKET_REGION_ENV = "POLICY_BUCKET_REGION"
POLICY_CONFIG_ROLE_ARN_ENV = "POLICY_CONFIG_ROLE_ARN"

DEFAULT_STATUS_RETRY_ATTEMPTS = 20
DEFAULT_STATUS_RETRY_DELAY_SECONDS = 15
DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS = 840
LAMBDA_TIMEOUT_BUFFER_SECONDS = 20
RDS_EVENT_SOURCE = "rds.amazonaws.com"

RDS_CREATION_EVENTS = {
    "CreateDBInstance": "DBInstance",
    "CreateDBInstanceReadReplica": "DBInstance",
    "RestoreDBInstanceFromDBSnapshot": "DBInstance",
    "RestoreDBInstanceFromS3": "DBInstance",
    "RestoreDBInstanceToPointInTime": "DBInstance",
    "CreateDBCluster": "DBCluster",
    "RestoreDBClusterFromSnapshot": "DBCluster",
    "RestoreDBClusterToPointInTime": "DBCluster",
}

EVENT_IDENTIFIER_KEYS = {
    "DBInstance": {
        "DBInstanceIdentifier",
        "dBInstanceIdentifier",
        "dbInstanceIdentifier",
    },
    "DBCluster": {
        "DBClusterIdentifier",
        "dBClusterIdentifier",
        "dbClusterIdentifier",
    },
}

RDS_RESOURCES = [
    {
        "api": "describe_db_instances",
        "result_key": "DBInstances",
        "type": "DBInstance",
        "id_key": "DBInstanceIdentifier",
        "arn_key": "DBInstanceArn",
        "status_key": "DBInstanceStatus",
        "delete_api": "delete_db_instance",
        "modify_api": "modify_db_instance",
        "id_arg": "DBInstanceIdentifier",
    },
    {
        "api": "describe_db_clusters",
        "result_key": "DBClusters",
        "type": "DBCluster",
        "id_key": "DBClusterIdentifier",
        "arn_key": "DBClusterArn",
        "status_key": "Status",
        "delete_api": "delete_db_cluster",
        "modify_api": "modify_db_cluster",
        "id_arg": "DBClusterIdentifier",
    },
]
RDS_RESOURCE_BY_TYPE = {resource["type"]: resource for resource in RDS_RESOURCES}
RDS_RESOURCE_TYPES = set(RDS_RESOURCE_BY_TYPE)


class RDSStatusTimeoutError(RuntimeError):
    pass


class PolicyConfigurationError(RuntimeError):
    pass


def resource_by_type(resource_type):
    return RDS_RESOURCE_BY_TYPE[resource_type]


def policy_s3_client(session, region_name=None, role_arn=None):
    if not role_arn:
        return session.client("s3", region_name=region_name)

    sts = session.client("sts")
    credentials = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="rds-guardrail-policy-reader",
    )["Credentials"]
    assumed_session = boto3.Session(
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )
    return assumed_session.client("s3", region_name=region_name)


def read_s3_json(s3, bucket, key):
    try:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        return json.loads(body)
    except (KeyError, TypeError, ValueError) as error:
        raise PolicyConfigurationError(
            f"Invalid JSON policy configuration in s3://{bucket}/{key}: {error}"
        ) from error


def normalize_policy(raw_policy):
    if not isinstance(raw_policy, dict) or not raw_policy:
        raise PolicyConfigurationError("Policy JSON must be a non-empty object.")

    policy = {}
    for engine, raw_rule in raw_policy.items():
        if not isinstance(engine, str) or not isinstance(raw_rule, dict):
            raise PolicyConfigurationError(
                "Each policy entry must map an engine name to an object."
            )
        rule = dict(raw_rule)
        if "minimum" in rule:
            minimum = rule["minimum"]
            if not isinstance(minimum, list) or not all(
                isinstance(part, int) for part in minimum
            ):
                raise PolicyConfigurationError(
                    f"Policy minimum for {engine} must be an array of integers."
                )
            rule["minimum"] = tuple(minimum)
        elif not isinstance(rule.get("minimum_major"), int):
            raise PolicyConfigurationError(
                f"Policy for {engine} requires minimum or minimum_major."
            )

        if not isinstance(rule.get("required"), str) or not isinstance(
            rule.get("message"), str
        ):
            raise PolicyConfigurationError(
                f"Policy for {engine} requires string required and message values."
            )
        policy[engine.lower()] = rule

    return policy


def normalize_policy_exceptions(raw_exceptions):
    if not isinstance(raw_exceptions, dict):
        raise PolicyConfigurationError("Policy exceptions JSON must be an object.")

    exceptions = {"DBInstance": set(), "DBCluster": set()}
    unknown_types = set(raw_exceptions) - RDS_RESOURCE_TYPES
    if unknown_types:
        raise PolicyConfigurationError(
            f"Unknown policy exception resource types: {sorted(unknown_types)}"
        )

    for resource_type, entries in raw_exceptions.items():
        if not isinstance(entries, list):
            raise PolicyConfigurationError(
                f"Policy exceptions for {resource_type} must be an array."
            )
        for entry in entries:
            if isinstance(entry, str):
                exceptions[resource_type].add(entry)
            elif (
                isinstance(entry, list)
                and len(entry) == 2
                and all(isinstance(value, str) for value in entry)
            ):
                exceptions[resource_type].add(tuple(entry))
            else:
                raise PolicyConfigurationError(
                    f"Invalid policy exception for {resource_type}: {entry!r}"
                )

    return exceptions


def load_policy_configuration(
    session,
    bucket=None,
    policy_key=None,
    policy_exceptions_key=None,
    bucket_region=None,
    role_arn=None,
):
    bucket = bucket or os.environ.get(POLICY_BUCKET_ENV)
    policy_key = policy_key or os.environ.get(POLICY_KEY_ENV)
    policy_exceptions_key = policy_exceptions_key or os.environ.get(
        POLICY_EXCEPTIONS_KEY_ENV
    )
    bucket_region = bucket_region or os.environ.get(POLICY_BUCKET_REGION_ENV)
    role_arn = role_arn or os.environ.get(POLICY_CONFIG_ROLE_ARN_ENV)
    missing = [
        name
        for name, value in (
            (POLICY_BUCKET_ENV, bucket),
            (POLICY_KEY_ENV, policy_key),
            (POLICY_EXCEPTIONS_KEY_ENV, policy_exceptions_key),
        )
        if not value
    ]
    if missing:
        raise PolicyConfigurationError(
            f"Missing policy configuration settings: {', '.join(missing)}"
        )

    s3 = policy_s3_client(session, bucket_region, role_arn)
    loaded_policy = normalize_policy(read_s3_json(s3, bucket, policy_key))
    loaded_exceptions = normalize_policy_exceptions(
        read_s3_json(s3, bucket, policy_exceptions_key)
    )

    POLICY.clear()
    POLICY.update(loaded_policy)
    POLICY_EXCEPTIONS.clear()
    POLICY_EXCEPTIONS.update(loaded_exceptions)
    return {
        "bucket": bucket,
        "policy_key": policy_key,
        "policy_exceptions_key": policy_exceptions_key,
        "assumed_role": bool(role_arn),
    }


def numbers(version):
    return tuple(int(part) for part in re.findall(r"\d+", version or ""))


def aurora_mysql_release(version):
    match = re.search(r"mysql_aurora\.(\d+\.\d+\.\d+)", version or "")
    return numbers(match.group(1)) if match else numbers(version)


def policy_result(engine, engine_version):
    engine = (engine or "").lower()
    rule = POLICY.get(engine)
    if not rule:
        return None

    if engine == "aurora-mysql":
        outdated = aurora_mysql_release(engine_version) < rule["minimum"]
    elif "minimum_major" in rule:
        current = numbers(engine_version)
        current_major = current[0] if current else 0
        outdated = current_major < rule["minimum_major"]
    else:
        outdated = numbers(engine_version) < rule["minimum"]

    if not outdated:
        return None

    return {
        "required_version": rule["required"],
        "reason": rule["message"],
    }


def account_id_from_arn(arn):
    parts = (arn or "").split(":", 5)
    return parts[4] if len(parts) == 6 else ""


def is_policy_exception(resource_type, identifier, account_id=""):
    normalized_identifier = (identifier or "").strip().lower()
    normalized_account_id = str(account_id or "").strip()

    for exception in POLICY_EXCEPTIONS.get(resource_type, set()):
        if isinstance(exception, str):
            if exception.strip().lower() == normalized_identifier:
                return True
            continue

        if isinstance(exception, (tuple, list)) and len(exception) == 2:
            exception_account_id, exception_identifier = exception
            if (
                str(exception_account_id).strip() == normalized_account_id
                and str(exception_identifier).strip().lower()
                == normalized_identifier
            ):
                return True

    return False


def policy_exception_from_item(region, resource, item):
    identifier = item.get(resource["id_key"], "")
    account_id = account_id_from_arn(item.get(resource["arn_key"], ""))
    engine = item.get("Engine", "")
    engine_version = item.get("EngineVersion", "")
    failed_policy = policy_result(engine, engine_version)
    if not failed_policy or not is_policy_exception(
        resource["type"], identifier, account_id
    ):
        return None

    return {
        "region": region,
        "account_id": account_id,
        "resource_type": resource["type"],
        "identifier": identifier,
        "status": item.get(resource["status_key"], ""),
        "engine": engine,
        "engine_version": engine_version,
        "required_version": failed_policy["required_version"],
        "result": "EXCEPTION",
        "reason": "Resource matched a configured policy exception",
    }


def enabled_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return sorted(region["RegionName"] for region in response["Regions"])


def paginate(client, operation, result_key):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate():
        yield from page.get(result_key, [])


def finding_from_item(region, resource, item):
    identifier = item.get(resource["id_key"], "")
    account_id = account_id_from_arn(item.get(resource["arn_key"], ""))
    if is_policy_exception(resource["type"], identifier, account_id):
        return None

    engine = item.get("Engine", "")
    engine_version = item.get("EngineVersion", "")
    failed_policy = policy_result(engine, engine_version)
    if not failed_policy:
        return None

    return {
        "region": region,
        "resource_type": resource["type"],
        "identifier": identifier,
        "status": item.get(resource["status_key"], ""),
        "engine": engine,
        "engine_version": engine_version,
        "deletion_protection": item.get("DeletionProtection", False),
        **failed_policy,
    }


def scan_region(session, region):
    rds = session.client("rds", region_name=region)
    findings = []
    exceptions = []

    for resource in RDS_RESOURCES:
        for item in paginate(rds, resource["api"], resource["result_key"]):
            exception = policy_exception_from_item(region, resource, item)
            if exception:
                exceptions.append(exception)
                continue
            finding = finding_from_item(region, resource, item)
            if finding:
                findings.append(finding)

    return findings, exceptions


def describe_resource(rds, resource, identifier):
    try:
        response = getattr(rds, resource["api"])(
            **{resource["id_arg"]: identifier}
        )
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code", "")
        if error_code in {
            "DBInstanceNotFound",
            "DBInstanceNotFoundFault",
            "DBClusterNotFound",
            "DBClusterNotFoundFault",
        }:
            return None
        raise

    items = response.get(resource["result_key"], [])
    return items[0] if items else None


def is_resource_not_found_error(error):
    error_code = error.response.get("Error", {}).get("Code", "")
    return error_code in {
        "DBInstanceNotFound",
        "DBInstanceNotFoundFault",
        "DBClusterNotFound",
        "DBClusterNotFoundFault",
    }


def wait_until_available(
    rds,
    resource,
    identifier,
    retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    wait_timeout_seconds=DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS,
    expected_deletion_protection=None,
    allow_not_found=False,
    acceptable_statuses=None,
):
    retry_delay_seconds = max(int(retry_delay_seconds), 1)
    wait_timeout_seconds = max(int(wait_timeout_seconds), 0)
    deadline = time.monotonic() + wait_timeout_seconds
    acceptable_statuses = set(acceptable_statuses or [])
    attempt = 0
    last_status = None
    last_deletion_protection = None

    while True:
        attempt += 1
        item = describe_resource(rds, resource, identifier)
        if item is None:
            if allow_not_found:
                return None, attempt

            raise RDSStatusTimeoutError(
                f"{resource['type']} {identifier} was not found while checking status."
            )

        last_status = item.get(resource["status_key"], "")
        last_deletion_protection = item.get("DeletionProtection", False)
        deletion_protection_matches = (
            expected_deletion_protection is None
            or last_deletion_protection == expected_deletion_protection
        )
        if last_status == "available" and deletion_protection_matches:
            return item, attempt
        if last_status in acceptable_statuses:
            return item, attempt

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            break

        if retry_delay_seconds:
            time.sleep(min(retry_delay_seconds, remaining_seconds))

    extra_status = ""
    if expected_deletion_protection is not None:
        extra_status = (
            f" Last deletion protection: {last_deletion_protection}."
        )

    raise RDSStatusTimeoutError(
        f"{resource['type']} {identifier} did not become available after "
        f"{wait_timeout_seconds} seconds and {attempt} status checks. "
        f"Last status: {last_status or 'unknown'}."
        f"{extra_status}"
    )


def wait_until_status_or_gone(
    rds,
    resource,
    identifier,
    target_statuses,
    retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    wait_timeout_seconds=DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS,
):
    retry_delay_seconds = max(int(retry_delay_seconds), 1)
    wait_timeout_seconds = max(int(wait_timeout_seconds), 0)
    deadline = time.monotonic() + wait_timeout_seconds
    attempt = 0
    last_status = None

    while True:
        attempt += 1
        item = describe_resource(rds, resource, identifier)
        if item is None:
            return "not-found", attempt

        last_status = item.get(resource["status_key"], "")
        if last_status in target_statuses:
            return last_status, attempt

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            break

        time.sleep(min(retry_delay_seconds, remaining_seconds))

    raise RDSStatusTimeoutError(
        f"{resource['type']} {identifier} did not reach one of "
        f"{sorted(target_statuses)} or disappear after {wait_timeout_seconds} "
        f"seconds and {attempt} status checks. Last status: "
        f"{last_status or 'unknown'}."
    )


def delete_cluster_members(
    rds,
    cluster,
    status_retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    status_wait_timeout_seconds=DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS,
):
    instance_resource = resource_by_type("DBInstance")
    actions = []

    for member in cluster.get("DBClusterMembers", []):
        member_identifier = member.get("DBInstanceIdentifier")
        if not member_identifier:
            continue

        member_item = describe_resource(rds, instance_resource, member_identifier)
        if member_item is None:
            actions.append(
                {
                    "identifier": member_identifier,
                    "status": "NOT_FOUND",
                    "delete_requested": False,
                    "status_checks": 0,
                }
            )
            continue

        member_action = {
            "identifier": member_identifier,
            "pre_delete_status": member_item.get(
                instance_resource["status_key"], ""
            ),
            "delete_requested": False,
            "delete_wait_status": "",
            "status_checks": 0,
        }

        member_status = member_item.get(instance_resource["status_key"], "")
        if member_status == "deleting":
            member_action["delete_wait_status"] = "deleting"
            actions.append(member_action)
            continue

        if member_status != "available":
            member_item, member_status_checks = wait_until_available(
                rds,
                instance_resource,
                member_identifier,
                retry_delay_seconds=status_retry_delay_seconds,
                wait_timeout_seconds=status_wait_timeout_seconds,
                allow_not_found=True,
                acceptable_statuses={"deleting"},
            )
            member_action["status_checks"] += member_status_checks
            if member_item is None:
                member_action["delete_wait_status"] = "not-found"
                actions.append(member_action)
                continue
            if member_item.get(instance_resource["status_key"], "") == "deleting":
                member_action["delete_wait_status"] = "deleting"
                actions.append(member_action)
                continue

        if member_item.get("DeletionProtection", False):
            getattr(rds, instance_resource["modify_api"])(
                **{
                    instance_resource["id_arg"]: member_identifier,
                    "DeletionProtection": False,
                    "ApplyImmediately": True,
                }
            )
            member_item, protection_status_checks = wait_until_available(
                rds,
                instance_resource,
                member_identifier,
                retry_delay_seconds=status_retry_delay_seconds,
                wait_timeout_seconds=status_wait_timeout_seconds,
                expected_deletion_protection=False,
                allow_not_found=True,
                acceptable_statuses={"deleting"},
            )
            member_action["status_checks"] += protection_status_checks
            if member_item is None:
                member_action["delete_wait_status"] = "not-found"
                actions.append(member_action)
                continue
            if member_item.get(instance_resource["status_key"], "") == "deleting":
                member_action["delete_wait_status"] = "deleting"
                actions.append(member_action)
                continue

        getattr(rds, instance_resource["delete_api"])(
            **{
                instance_resource["id_arg"]: member_identifier,
                "SkipFinalSnapshot": True,
            }
        )
        member_action["delete_requested"] = True

        delete_wait_status, delete_status_checks = wait_until_status_or_gone(
            rds,
            instance_resource,
            member_identifier,
            {"deleting"},
            retry_delay_seconds=status_retry_delay_seconds,
            wait_timeout_seconds=status_wait_timeout_seconds,
        )
        member_action["delete_wait_status"] = delete_wait_status
        member_action["status_checks"] += delete_status_checks
        actions.append(member_action)

    return actions


def delete_finding(
    rds,
    finding,
    status_retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    status_retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    status_wait_timeout_seconds=DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS,
):
    resource = resource_by_type(finding["resource_type"])
    identifier = finding["identifier"]
    item, status_checks = wait_until_available(
        rds,
        resource,
        identifier,
        retry_attempts=status_retry_attempts,
        retry_delay_seconds=status_retry_delay_seconds,
        wait_timeout_seconds=status_wait_timeout_seconds,
        allow_not_found=True,
        acceptable_statuses={"deleting"},
    )
    if item is None:
        return {
            "region": finding["region"],
            "resource_type": finding["resource_type"],
            "identifier": identifier,
            "pre_delete_status": finding.get("status", ""),
            "status_checks": status_checks,
            "deletion_protection_removed": False,
            "final_snapshot_skipped": True,
            "snapshots_deleted": False,
            "cluster_member_delete_actions": [],
            "status": "ALREADY_DELETED",
        }

    action = {
        "region": finding["region"],
        "resource_type": finding["resource_type"],
        "identifier": identifier,
        "pre_delete_status": item.get(resource["status_key"], ""),
        "status_checks": status_checks,
        "deletion_protection_removed": False,
        "final_snapshot_skipped": True,
        "snapshots_deleted": False,
        "cluster_member_delete_actions": [],
        "status": "DELETE_REQUESTED",
    }

    if item.get(resource["status_key"], "") == "deleting":
        action["status"] = "DELETE_IN_PROGRESS"
        return action

    if item.get("DeletionProtection", False):
        getattr(rds, resource["modify_api"])(
            **{
                resource["id_arg"]: identifier,
                "DeletionProtection": False,
                "ApplyImmediately": True,
            }
        )
        action["deletion_protection_removed"] = True
        item, protection_status_checks = wait_until_available(
            rds,
            resource,
            identifier,
            retry_attempts=status_retry_attempts,
            retry_delay_seconds=status_retry_delay_seconds,
            wait_timeout_seconds=status_wait_timeout_seconds,
            expected_deletion_protection=False,
            allow_not_found=True,
            acceptable_statuses={"deleting"},
        )
        if item is None:
            action["status"] = "ALREADY_DELETED"
            action["status_checks"] += protection_status_checks
            return action

        action["pre_delete_status"] = item.get(resource["status_key"], "")
        action["status_checks"] += protection_status_checks
        if item.get(resource["status_key"], "") == "deleting":
            action["status"] = "DELETE_IN_PROGRESS"
            return action

    if resource["type"] == "DBCluster":
        cluster_member_actions = delete_cluster_members(
            rds,
            item,
            status_retry_delay_seconds=status_retry_delay_seconds,
            status_wait_timeout_seconds=status_wait_timeout_seconds,
        )
        action["cluster_member_delete_actions"] = cluster_member_actions
        action["status_checks"] += sum(
            member_action["status_checks"]
            for member_action in cluster_member_actions
        )
        item, cluster_status_checks = wait_until_available(
            rds,
            resource,
            identifier,
            retry_delay_seconds=status_retry_delay_seconds,
            wait_timeout_seconds=status_wait_timeout_seconds,
            allow_not_found=True,
            acceptable_statuses={"deleting"},
        )
        if item is None:
            action["status"] = "ALREADY_DELETED"
            action["status_checks"] += cluster_status_checks
            return action

        action["pre_delete_status"] = item.get(resource["status_key"], "")
        action["status_checks"] += cluster_status_checks
        if item.get(resource["status_key"], "") == "deleting":
            action["status"] = "DELETE_IN_PROGRESS"
            return action

    delete_args = {
        resource["id_arg"]: identifier,
        "SkipFinalSnapshot": True,
    }

    try:
        getattr(rds, resource["delete_api"])(**delete_args)
    except ClientError as error:
        if is_resource_not_found_error(error):
            action["status"] = "ALREADY_DELETED"
            return action
        raise

    return action


def delete_findings(
    session,
    findings,
    status_retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    status_retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    status_wait_timeout_seconds=DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS,
):
    actions = []
    errors = []
    clients = {}

    for finding in findings:
        region = finding["region"]
        try:
            if region not in clients:
                clients[region] = session.client("rds", region_name=region)
            actions.append(
                delete_finding(
                    clients[region],
                    finding,
                    status_retry_attempts=status_retry_attempts,
                    status_retry_delay_seconds=status_retry_delay_seconds,
                    status_wait_timeout_seconds=status_wait_timeout_seconds,
                )
            )
        except (BotoCoreError, ClientError, RDSStatusTimeoutError) as error:
            errors.append(
                {
                    "region": region,
                    "resource_type": finding["resource_type"],
                    "identifier": finding["identifier"],
                    "error": str(error),
                }
            )

    return actions, errors


def find_nested_value(data, candidate_keys):
    if isinstance(data, dict):
        for key in candidate_keys:
            value = data.get(key)
            if value:
                return value

        for value in data.values():
            nested_value = find_nested_value(value, candidate_keys)
            if nested_value:
                return nested_value

    if isinstance(data, list):
        for item in data:
            nested_value = find_nested_value(item, candidate_keys)
            if nested_value:
                return nested_value

    return None


def normalize_target(target):
    if not isinstance(target, dict):
        return None

    region = target.get("region")
    resource_type = target.get("resource_type") or target.get("resourceType")
    identifier = target.get("identifier")

    if resource_type not in RDS_RESOURCE_TYPES:
        return None

    if not region or not identifier:
        return None

    return {
        "region": region,
        "resource_type": resource_type,
        "identifier": identifier,
    }


def has_target_input(event):
    if not isinstance(event, dict):
        return False

    if "targets" in event or "target" in event:
        return True

    return any(key in event for key in ("identifier", "resource_type", "resourceType"))


def eventbridge_target(event):
    detail = event.get("detail") if isinstance(event, dict) else None
    if not isinstance(detail, dict):
        return None

    if detail.get("eventSource") != RDS_EVENT_SOURCE:
        return None

    event_name = detail.get("eventName")
    resource_type = RDS_CREATION_EVENTS.get(event_name)
    if not resource_type:
        return None

    identifier = find_nested_value(
        [detail.get("responseElements"), detail.get("requestParameters")],
        EVENT_IDENTIFIER_KEYS[resource_type],
    )
    region = detail.get("awsRegion") or event.get("region")
    return normalize_target(
        {
            "region": region,
            "resource_type": resource_type,
            "identifier": identifier,
        }
    )


def event_targets(event):
    targets = []
    explicit_targets = event.get("targets") if isinstance(event, dict) else None
    explicit_target = event.get("target") if isinstance(event, dict) else None
    if isinstance(explicit_targets, list):
        for target in explicit_targets:
            normalized_target = normalize_target(target)
            if normalized_target:
                targets.append(normalized_target)
    elif isinstance(explicit_targets, dict):
        normalized_target = normalize_target(explicit_targets)
        if normalized_target:
            targets.append(normalized_target)
    elif isinstance(explicit_target, dict):
        normalized_target = normalize_target(explicit_target)
        if normalized_target:
            targets.append(normalized_target)
    else:
        normalized_target = normalize_target(event)
        if normalized_target:
            targets.append(normalized_target)

    event_target = eventbridge_target(event)
    if event_target:
        targets.append(event_target)

    seen = set()
    unique_targets = []
    for target in targets:
        key = (target["region"], target["resource_type"], target["identifier"])
        if key in seen:
            continue
        seen.add(key)
        unique_targets.append(target)

    return unique_targets


def response(result):
    print(json.dumps(result, default=str))
    return result


def scan_targets(session, targets):
    findings = []
    exceptions = []
    errors = []
    clients = {}

    for target in targets:
        region = target["region"]
        resource = resource_by_type(target["resource_type"])
        try:
            if region not in clients:
                clients[region] = session.client("rds", region_name=region)
            rds = clients[region]
            item = describe_resource(rds, resource, target["identifier"])
            if item is None:
                continue

            exception = policy_exception_from_item(region, resource, item)
            if exception:
                exceptions.append(exception)
                continue

            finding = finding_from_item(region, resource, item)
            if finding:
                findings.append(finding)
        except (BotoCoreError, ClientError) as error:
            errors.append(
                {
                    "region": region,
                    "resource_type": target["resource_type"],
                    "identifier": target["identifier"],
                    "error": str(error),
                }
            )

    return findings, exceptions, errors


def scan_account(
    session=None,
    regions=None,
    delete_outdated=False,
    status_retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    status_retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    status_wait_timeout_seconds=DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS,
):
    if IMPORT_ERROR is not None:
        raise RuntimeError(f"Missing required Python package: {IMPORT_ERROR.name}")

    session = session or boto3.Session()
    regions = regions or enabled_regions(session)
    findings = []
    exceptions = []
    errors = []

    for region in regions:
        try:
            region_findings, region_exceptions = scan_region(session, region)
            findings.extend(region_findings)
            exceptions.extend(region_exceptions)
        except (BotoCoreError, ClientError) as error:
            errors.append({"region": region, "error": str(error)})

    delete_actions = []
    if delete_outdated and findings:
        actions, delete_errors = delete_findings(
            session,
            findings,
            status_retry_attempts=status_retry_attempts,
            status_retry_delay_seconds=status_retry_delay_seconds,
            status_wait_timeout_seconds=status_wait_timeout_seconds,
        )
        delete_actions.extend(actions)
        errors.extend(delete_errors)

    status = "ERROR" if errors else "FAIL" if findings else "PASS"
    if delete_outdated and findings and not errors:
        status = "DELETE_REQUESTED"

    return {
        "status": status,
        "finding_count": len(findings),
        "findings": findings,
        "exception_count": len(exceptions),
        "exceptions": exceptions,
        "delete_action_count": len(delete_actions),
        "delete_actions": delete_actions,
        "errors": errors,
    }


def print_table(findings, exceptions=None):
    exceptions = exceptions or []
    results = [
        {**finding, "result": "FAIL"}
        for finding in findings
    ] + exceptions
    if not results:
        print("No outdated RDS resources found.")
        return

    headers = [
        "Region",
        "Type",
        "Identifier",
        "Engine",
        "Current",
        "Required",
        "Result",
        "Reason",
    ]
    rows = [
        [
            finding["region"],
            finding["resource_type"],
            finding["identifier"],
            finding["engine"],
            finding["engine_version"],
            finding["required_version"],
            finding["result"],
            finding["reason"],
        ]
        for finding in results
    ]
    widths = [
        max(len(str(row[index])) for row in [headers, *rows])
        for index in range(len(headers))
    ]

    print(" | ".join(header.ljust(widths[index]) for index, header in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(str(value).ljust(widths[index]) for index, value in enumerate(row)))


def lambda_handler(event, context):
    event = event or {}
    if IMPORT_ERROR is not None:
        raise RuntimeError(f"Missing required Python package: {IMPORT_ERROR.name}")

    status_retry_attempts = event.get(
        "status_retry_attempts", DEFAULT_STATUS_RETRY_ATTEMPTS
    )
    status_retry_delay_seconds = event.get(
        "status_retry_delay_seconds", DEFAULT_STATUS_RETRY_DELAY_SECONDS
    )
    status_wait_timeout_seconds = event.get(
        "status_wait_timeout_seconds", DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS
    )
    if context and hasattr(context, "get_remaining_time_in_millis"):
        remaining_seconds = max(
            int(context.get_remaining_time_in_millis() / 1000)
            - LAMBDA_TIMEOUT_BUFFER_SECONDS,
            1,
        )
        status_wait_timeout_seconds = min(
            int(status_wait_timeout_seconds), remaining_seconds
        )

    targets = event_targets(event)

    if not targets and event.get("detail"):
        return response({
            "status": "PASS",
            "event_ignored": True,
            "ignore_reason": (
                "Lambda deletes only RDS create or restore EventBridge events. "
                "Existing resources and modify/scale events are ignored."
            ),
            "target_count": 0,
            "targets": [],
            "finding_count": 0,
            "findings": [],
            "exception_count": 0,
            "exceptions": [],
            "delete_action_count": 0,
            "delete_actions": [],
            "errors": [],
        })

    if not targets and has_target_input(event):
        return response({
            "status": "ERROR",
            "event_ignored": False,
            "target_count": 0,
            "targets": [],
            "finding_count": 0,
            "findings": [],
            "exception_count": 0,
            "exceptions": [],
            "delete_action_count": 0,
            "delete_actions": [],
            "errors": [
                {
                    "error": (
                        "Target input was provided but no valid target could be parsed. "
                        "Use region, resource_type, and identifier for each target."
                    )
                }
            ],
        })

    session = boto3.Session()
    try:
        policy_configuration = load_policy_configuration(session)
    except (BotoCoreError, ClientError, PolicyConfigurationError) as error:
        return response({
            "status": "ERROR",
            "event_ignored": False,
            "target_count": len(targets),
            "targets": targets,
            "finding_count": 0,
            "findings": [],
            "exception_count": 0,
            "exceptions": [],
            "delete_action_count": 0,
            "delete_actions": [],
            "errors": [{"error": f"Unable to load policy configuration: {error}"}],
        })

    if targets:
        findings, exceptions, errors = scan_targets(session, targets)
        delete_actions = []
        if findings:
            actions, delete_errors = delete_findings(
                session,
                findings,
                status_retry_attempts=status_retry_attempts,
                status_retry_delay_seconds=status_retry_delay_seconds,
                status_wait_timeout_seconds=status_wait_timeout_seconds,
            )
            delete_actions.extend(actions)
            errors.extend(delete_errors)

        status = "ERROR" if errors else "DELETE_REQUESTED" if findings else "PASS"
        return response({
            "status": status,
            "target_count": len(targets),
            "targets": targets,
            "finding_count": len(findings),
            "findings": findings,
            "exception_count": len(exceptions),
            "exceptions": exceptions,
            "delete_action_count": len(delete_actions),
            "delete_actions": delete_actions,
            "policy_configuration": policy_configuration,
            "status_wait_timeout_seconds": status_wait_timeout_seconds,
            "errors": errors,
        })

    result = scan_account(
        session=session,
        regions=event.get("regions"),
        delete_outdated=False,
        status_retry_attempts=status_retry_attempts,
        status_retry_delay_seconds=status_retry_delay_seconds,
        status_wait_timeout_seconds=status_wait_timeout_seconds,
    )
    result["event_ignored"] = False
    result["policy_configuration"] = policy_configuration
    return response(result)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Find RDS MySQL, Aurora MySQL, and PostgreSQL resources below minimum versions."
    )
    parser.add_argument("--profile", help="AWS profile name to use.")
    parser.add_argument("--regions", nargs="+", help="AWS regions to scan.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    parser.add_argument(
        "--policy-bucket",
        help=f"S3 policy bucket. Defaults to ${POLICY_BUCKET_ENV}.",
    )
    parser.add_argument(
        "--policy-key",
        help=f"S3 version policy object key. Defaults to ${POLICY_KEY_ENV}.",
    )
    parser.add_argument(
        "--policy-exceptions-key",
        help=(
            "S3 policy exceptions object key. Defaults to "
            f"${POLICY_EXCEPTIONS_KEY_ENV}."
        ),
    )
    parser.add_argument(
        "--policy-bucket-region",
        help=f"S3 bucket region. Defaults to ${POLICY_BUCKET_REGION_ENV}.",
    )
    parser.add_argument(
        "--policy-config-role-arn",
        help=(
            "Optional cross-account role to assume before reading S3. "
            f"Defaults to ${POLICY_CONFIG_ROLE_ARN_ENV}."
        ),
    )
    parser.add_argument(
        "--delete-outdated",
        action="store_true",
        help=(
            "Delete DB instances and clusters that are below the configured "
            "policy. Final snapshots are always skipped."
        ),
    )
    parser.add_argument(
        "--status-retry-attempts",
        type=int,
        default=DEFAULT_STATUS_RETRY_ATTEMPTS,
        help=(
            "Deprecated compatibility option. Status waiting is controlled by "
            "--status-wait-timeout-seconds."
        ),
    )
    parser.add_argument(
        "--status-retry-delay-seconds",
        type=int,
        default=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
        help="Seconds to wait between RDS status checks.",
    )
    parser.add_argument(
        "--status-wait-timeout-seconds",
        type=int,
        default=DEFAULT_STATUS_WAIT_TIMEOUT_SECONDS,
        help="Maximum seconds to wait for an RDS resource to become available.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if IMPORT_ERROR is not None:
        print(f"Missing required Python package '{IMPORT_ERROR.name}'.", file=sys.stderr)
        print("Install the AWS SDK with: python3 -m pip install boto3", file=sys.stderr)
        return 2

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    try:
        policy_configuration = load_policy_configuration(
            session,
            bucket=args.policy_bucket,
            policy_key=args.policy_key,
            policy_exceptions_key=args.policy_exceptions_key,
            bucket_region=args.policy_bucket_region,
            role_arn=args.policy_config_role_arn,
        )
    except (BotoCoreError, ClientError, PolicyConfigurationError) as error:
        print(f"Unable to load policy configuration: {error}", file=sys.stderr)
        return 2

    result = scan_account(
        session=session,
        regions=args.regions,
        delete_outdated=args.delete_outdated,
        status_retry_attempts=args.status_retry_attempts,
        status_retry_delay_seconds=args.status_retry_delay_seconds,
        status_wait_timeout_seconds=args.status_wait_timeout_seconds,
    )
    result["policy_configuration"] = policy_configuration

    if result["errors"]:
        print(json.dumps(result["errors"], indent=2), file=sys.stderr)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_table(result["findings"], result["exceptions"])
        if result["delete_actions"]:
            print()
            print(f"Delete requested for {result['delete_action_count']} resources.")

    if result["errors"]:
        return 2

    return 1 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
