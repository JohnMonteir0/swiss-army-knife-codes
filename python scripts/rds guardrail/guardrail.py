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

Lambda event example:
  {"regions": ["us-east-1", "us-west-2"]}
"""

import argparse
import json
import re
import sys

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

RDS_RESOURCES = [
    {
        "api": "describe_db_instances",
        "result_key": "DBInstances",
        "type": "DBInstance",
        "id_key": "DBInstanceIdentifier",
    },
    {
        "api": "describe_db_clusters",
        "result_key": "DBClusters",
        "type": "DBCluster",
        "id_key": "DBClusterIdentifier",
    },
]


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


def scan_region(session, region):
    rds = session.client("rds", region_name=region)
    findings = []

    for resource in RDS_RESOURCES:
        for item in paginate(rds, resource["api"], resource["result_key"]):
            engine = item.get("Engine", "")
            engine_version = item.get("EngineVersion", "")
            failed_policy = policy_result(engine, engine_version)
            if not failed_policy:
                continue

            findings.append(
                {
                    "region": region,
                    "resource_type": resource["type"],
                    "identifier": item.get(resource["id_key"], ""),
                    "engine": engine,
                    "engine_version": engine_version,
                    **failed_policy,
                }
            )

    return findings


def scan_account(session=None, regions=None):
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

    status = "ERROR" if errors else "FAIL" if findings else "PASS"

    return {
        "status": status,
        "finding_count": len(findings),
        "findings": findings,
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
    regions = event.get("regions")
    result = scan_account(regions=regions)

    # Raising an exception marks the Lambda invocation as failed, which is useful
    # when the function runs as a CI/CD or EventBridge guardrail.
    if result["findings"] or result["errors"]:
        raise Exception(json.dumps(result, default=str))

    return result


def parse_args():
    parser = argparse.ArgumentParser(
        description="Find RDS MySQL, Aurora MySQL, and PostgreSQL resources below minimum versions."
    )
    parser.add_argument("--profile", help="AWS profile name to use.")
    parser.add_argument("--regions", nargs="+", help="AWS regions to scan.")
    parser.add_argument("--json", action="store_true", help="Print JSON output.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if IMPORT_ERROR is not None:
        print(f"Missing required Python package '{IMPORT_ERROR.name}'.", file=sys.stderr)
        print("Install the AWS SDK with: python3 -m pip install boto3", file=sys.stderr)
        return 2

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    result = scan_account(session=session, regions=args.regions)

    if result["errors"]:
        print(json.dumps(result["errors"], indent=2), file=sys.stderr)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_table(result["findings"])

    if result["errors"]:
        return 2

    return 1 if result["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
