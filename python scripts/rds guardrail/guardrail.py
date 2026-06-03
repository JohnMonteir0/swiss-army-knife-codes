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
  {"regions": ["us-east-1"], "status_retry_attempts": 20}
  {"targets": [{"region": "us-east-1", "resource_type": "DBInstance", "identifier": "test-db"}]}
"""

import argparse
import json
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


# DevOps-friendly guardrail configuration. Change only this block when policy changes.
POLICY = {
    "mysql": {
        "minimum": (8, 4, 7),
        "required": "8.4.7",
        "message": "MySQL version is below 8.4.7",
    },
    "aurora-mysql": {
        "minimum": (3, 10, 3),
        "required": "8.0.mysql_aurora.3.10.3",
        "message": "Aurora MySQL version is below 8.0.mysql_aurora.3.10.3",
    },
    "postgres": {
        "minimum_major": 17,
        "required": "17",
        "message": "PostgreSQL major version is below 17",
    },
}

DEFAULT_STATUS_RETRY_ATTEMPTS = 20
DEFAULT_STATUS_RETRY_DELAY_SECONDS = 15
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
        "status_key": "Status",
        "delete_api": "delete_db_cluster",
        "modify_api": "modify_db_cluster",
        "id_arg": "DBClusterIdentifier",
    },
]


class RDSStatusTimeoutError(RuntimeError):
    pass


def resource_by_type(resource_type):
    return next(item for item in RDS_RESOURCES if item["type"] == resource_type)


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


def enabled_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return sorted(region["RegionName"] for region in response["Regions"])


def paginate(client, operation, result_key):
    paginator = client.get_paginator(operation)
    for page in paginator.paginate():
        yield from page.get(result_key, [])


def finding_from_item(region, resource, item):
    engine = item.get("Engine", "")
    engine_version = item.get("EngineVersion", "")
    failed_policy = policy_result(engine, engine_version)
    if not failed_policy:
        return None

    return {
        "region": region,
        "resource_type": resource["type"],
        "identifier": item.get(resource["id_key"], ""),
        "status": item.get(resource["status_key"], ""),
        "engine": engine,
        "engine_version": engine_version,
        "deletion_protection": item.get("DeletionProtection", False),
        **failed_policy,
    }


def scan_region(session, region):
    rds = session.client("rds", region_name=region)
    findings = []

    for resource in RDS_RESOURCES:
        for item in paginate(rds, resource["api"], resource["result_key"]):
            finding = finding_from_item(region, resource, item)
            if finding:
                findings.append(finding)

    return findings


def describe_resource(rds, resource, identifier):
    response = getattr(rds, resource["api"])(
        **{resource["id_arg"]: identifier}
    )
    items = response.get(resource["result_key"], [])
    return items[0] if items else None


def wait_until_available(
    rds,
    resource,
    identifier,
    retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
    expected_deletion_protection=None,
):
    retry_attempts = max(int(retry_attempts), 1)
    retry_delay_seconds = max(int(retry_delay_seconds), 0)
    last_status = None
    last_deletion_protection = None

    for attempt in range(1, retry_attempts + 1):
        item = describe_resource(rds, resource, identifier)
        if item is None:
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

        if attempt < retry_attempts and retry_delay_seconds:
            time.sleep(retry_delay_seconds)

    extra_status = ""
    if expected_deletion_protection is not None:
        extra_status = (
            f" Last deletion protection: {last_deletion_protection}."
        )

    raise RDSStatusTimeoutError(
        f"{resource['type']} {identifier} did not become available after "
        f"{retry_attempts} status checks. Last status: {last_status or 'unknown'}."
        f"{extra_status}"
    )


def delete_finding(
    rds,
    finding,
    status_retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    status_retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
):
    resource = resource_by_type(finding["resource_type"])
    identifier = finding["identifier"]
    item, status_checks = wait_until_available(
        rds,
        resource,
        identifier,
        retry_attempts=status_retry_attempts,
        retry_delay_seconds=status_retry_delay_seconds,
    )
    action = {
        "region": finding["region"],
        "resource_type": finding["resource_type"],
        "identifier": identifier,
        "pre_delete_status": item.get(resource["status_key"], ""),
        "status_checks": status_checks,
        "deletion_protection_removed": False,
        "final_snapshot_skipped": True,
        "snapshots_deleted": False,
        "status": "DELETE_REQUESTED",
    }

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
            expected_deletion_protection=False,
        )
        action["pre_delete_status"] = item.get(resource["status_key"], "")
        action["status_checks"] += protection_status_checks

    delete_args = {
        resource["id_arg"]: identifier,
        "SkipFinalSnapshot": True,
    }

    getattr(rds, resource["delete_api"])(**delete_args)
    return action


def delete_findings(
    session,
    findings,
    status_retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    status_retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
):
    actions = []
    errors = []
    clients = {}

    for finding in findings:
        region = finding["region"]
        try:
            clients.setdefault(region, session.client("rds", region_name=region))
            actions.append(
                delete_finding(
                    clients[region],
                    finding,
                    status_retry_attempts=status_retry_attempts,
                    status_retry_delay_seconds=status_retry_delay_seconds,
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

    if resource_type not in {resource["type"] for resource in RDS_RESOURCES}:
        return None

    if not region or not identifier:
        return None

    return {
        "region": region,
        "resource_type": resource_type,
        "identifier": identifier,
    }


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
    if isinstance(explicit_targets, list):
        for target in explicit_targets:
            normalized_target = normalize_target(target)
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


def scan_targets(session, targets):
    findings = []
    errors = []

    for target in targets:
        region = target["region"]
        resource = resource_by_type(target["resource_type"])
        try:
            rds = session.client("rds", region_name=region)
            item = describe_resource(rds, resource, target["identifier"])
            if item is None:
                errors.append(
                    {
                        "region": region,
                        "resource_type": target["resource_type"],
                        "identifier": target["identifier"],
                        "error": "Resource was not found.",
                    }
                )
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

    return findings, errors


def scan_account(
    session=None,
    regions=None,
    delete_outdated=False,
    status_retry_attempts=DEFAULT_STATUS_RETRY_ATTEMPTS,
    status_retry_delay_seconds=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
):
    if IMPORT_ERROR is not None:
        raise RuntimeError(f"Missing required Python package: {IMPORT_ERROR.name}")

    session = session or boto3.Session()
    regions = regions or enabled_regions(session)
    findings = []
    errors = []

    for region in regions:
        try:
            findings.extend(scan_region(session, region))
        except (BotoCoreError, ClientError) as error:
            errors.append({"region": region, "error": str(error)})

    delete_actions = []
    if delete_outdated and findings:
        actions, delete_errors = delete_findings(
            session,
            findings,
            status_retry_attempts=status_retry_attempts,
            status_retry_delay_seconds=status_retry_delay_seconds,
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
        "delete_action_count": len(delete_actions),
        "delete_actions": delete_actions,
        "errors": errors,
    }


def print_table(findings):
    if not findings:
        print("No outdated RDS resources found.")
        return

    headers = [
        "Region",
        "Type",
        "Identifier",
        "Engine",
        "Current",
        "Required",
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
            finding["reason"],
        ]
        for finding in findings
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
    targets = event_targets(event)

    if not targets and event.get("detail"):
        return {
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
            "delete_action_count": 0,
            "delete_actions": [],
            "errors": [],
        }

    session = boto3.Session()

    if targets:
        findings, errors = scan_targets(session, targets)
        delete_actions = []
        if findings:
            actions, delete_errors = delete_findings(
                session,
                findings,
                status_retry_attempts=status_retry_attempts,
                status_retry_delay_seconds=status_retry_delay_seconds,
            )
            delete_actions.extend(actions)
            errors.extend(delete_errors)

        status = "ERROR" if errors else "DELETE_REQUESTED" if findings else "PASS"
        return {
            "status": status,
            "target_count": len(targets),
            "targets": targets,
            "finding_count": len(findings),
            "findings": findings,
            "delete_action_count": len(delete_actions),
            "delete_actions": delete_actions,
            "errors": errors,
        }

    result = scan_account(
        session=session,
        regions=event.get("regions"),
        delete_outdated=False,
        status_retry_attempts=status_retry_attempts,
        status_retry_delay_seconds=status_retry_delay_seconds,
    )
    result["event_ignored"] = False
    return result


def parse_args():
    parser = argparse.ArgumentParser(
        description="Find RDS MySQL, Aurora MySQL, and PostgreSQL resources below minimum versions."
    )
    parser.add_argument("--profile", help="AWS profile name to use.")
    parser.add_argument("--regions", nargs="+", help="AWS regions to scan.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
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
        help="Number of status checks before deleting a resource.",
    )
    parser.add_argument(
        "--status-retry-delay-seconds",
        type=int,
        default=DEFAULT_STATUS_RETRY_DELAY_SECONDS,
        help="Seconds to wait between RDS status checks.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if IMPORT_ERROR is not None:
        print(f"Missing required Python package '{IMPORT_ERROR.name}'.", file=sys.stderr)
        print("Install the AWS SDK with: python3 -m pip install boto3", file=sys.stderr)
        return 2

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    result = scan_account(
        session=session,
        regions=args.regions,
        delete_outdated=args.delete_outdated,
        status_retry_attempts=args.status_retry_attempts,
        status_retry_delay_seconds=args.status_retry_delay_seconds,
    )

    if result["errors"]:
        print(json.dumps(result["errors"], indent=2), file=sys.stderr)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_table(result["findings"])
        if result["delete_actions"]:
            print()
            print(f"Delete requested for {result['delete_action_count']} resources.")

    if result["errors"]:
        return 2

    return 1 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
