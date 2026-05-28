#!/usr/bin/env python3
"""
Scan an AWS account for RDS engines below the approved minimum versions.

Requires:
  pip install boto3

Examples:
  python guardrail.py
  python guardrail.py --profile my-profile
  python guardrail.py --regions us-east-1 us-west-2 --json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from typing import Iterable

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


MIN_MYSQL = (8, 4, 7)
MIN_AURORA_MYSQL = (3, 10, 3)
MIN_POSTGRES_MAJOR = 17


@dataclass
class Finding:
    region: str
    resource_type: str
    identifier: str
    engine: str
    engine_version: str
    required_version: str
    reason: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Find RDS MySQL, Aurora MySQL, and PostgreSQL resources below minimum versions."
    )
    parser.add_argument("--profile", help="AWS profile name to use.")
    parser.add_argument(
        "--regions",
        nargs="+",
        help="AWS regions to scan. Defaults to all enabled commercial regions.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print findings as JSON instead of a table.",
    )
    return parser.parse_args()


def validate_dependencies() -> bool:
    if IMPORT_ERROR is None:
        return True

    print(
        f"Missing required Python package '{IMPORT_ERROR.name}'.",
        file=sys.stderr,
    )
    print("Install the AWS SDK with: python3 -m pip install boto3", file=sys.stderr)
    return False


def version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", version))


def aurora_mysql_version_tuple(version: str) -> tuple[int, ...]:
    match = re.search(r"mysql_aurora\.(\d+\.\d+\.\d+)", version)
    if match:
        return version_tuple(match.group(1))

    # Some AWS responses may use only the Aurora release number.
    return version_tuple(version)


def is_outdated(engine: str, engine_version: str) -> tuple[bool, str, str]:
    normalized_engine = engine.lower()

    if normalized_engine == "mysql":
        current = version_tuple(engine_version)
        return (
            current < MIN_MYSQL,
            "8.4.7",
            "MySQL version is below 8.4.7",
        )

    if normalized_engine == "aurora-mysql":
        current = aurora_mysql_version_tuple(engine_version)
        return (
            current < MIN_AURORA_MYSQL,
            "8.0.mysql_aurora.3.10.3",
            "Aurora MySQL version is below 8.0.mysql_aurora.3.10.3",
        )

    if normalized_engine in {"postgres", "aurora-postgresql"}:
        current = version_tuple(engine_version)
        current_major = current[0] if current else 0
        return (
            current_major < MIN_POSTGRES_MAJOR,
            "17",
            "PostgreSQL major version is below 17",
        )

    return False, "", ""


def enabled_regions(session: boto3.Session) -> list[str]:
    ec2 = session.client("ec2", region_name="us-east-1")
    response = ec2.describe_regions(AllRegions=False)
    return sorted(region["RegionName"] for region in response["Regions"])


def paginate(client, operation: str, result_key: str) -> Iterable[dict]:
    paginator = client.get_paginator(operation)
    for page in paginator.paginate():
        yield from page.get(result_key, [])


def scan_instances(session: boto3.Session, region: str) -> list[Finding]:
    rds = session.client("rds", region_name=region)
    findings: list[Finding] = []

    for db in paginate(rds, "describe_db_instances", "DBInstances"):
        engine = db.get("Engine", "")
        engine_version = db.get("EngineVersion", "")
        outdated, required_version, reason = is_outdated(engine, engine_version)

        if outdated:
            findings.append(
                Finding(
                    region=region,
                    resource_type="DBInstance",
                    identifier=db.get("DBInstanceIdentifier", ""),
                    engine=engine,
                    engine_version=engine_version,
                    required_version=required_version,
                    reason=reason,
                )
            )

    return findings


def scan_clusters(session: boto3.Session, region: str) -> list[Finding]:
    rds = session.client("rds", region_name=region)
    findings: list[Finding] = []

    for cluster in paginate(rds, "describe_db_clusters", "DBClusters"):
        engine = cluster.get("Engine", "")
        engine_version = cluster.get("EngineVersion", "")
        outdated, required_version, reason = is_outdated(engine, engine_version)

        if outdated:
            findings.append(
                Finding(
                    region=region,
                    resource_type="DBCluster",
                    identifier=cluster.get("DBClusterIdentifier", ""),
                    engine=engine,
                    engine_version=engine_version,
                    required_version=required_version,
                    reason=reason,
                )
            )

    return findings


def print_table(findings: list[Finding]) -> None:
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
            finding.region,
            finding.resource_type,
            finding.identifier,
            finding.engine,
            finding.engine_version,
            finding.required_version,
            finding.reason,
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


def main() -> int:
    args = parse_args()
    if not validate_dependencies():
        return 2

    session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()

    try:
        regions = args.regions or enabled_regions(session)
    except (BotoCoreError, ClientError) as error:
        print(f"Failed to list AWS regions: {error}", file=sys.stderr)
        return 2

    findings: list[Finding] = []
    for region in regions:
        try:
            findings.extend(scan_instances(session, region))
            findings.extend(scan_clusters(session, region))
        except (BotoCoreError, ClientError) as error:
            print(f"Failed to scan {region}: {error}", file=sys.stderr)

    if args.json:
        print(json.dumps([asdict(finding) for finding in findings], indent=2))
    else:
        print_table(findings)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
