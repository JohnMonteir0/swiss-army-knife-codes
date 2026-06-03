# RDS Guardrail Lambda Runbook

This Lambda scans RDS DB instances and DB clusters for engine versions below the policy in `guardrail.py`.
When EventBridge invokes it for an RDS create or restore API event, it checks only the resource from that event and deletes it only when it violates the version policy. RDS resources that existed before the event are not deleted. Modify and scale events are ignored.

## Lambda Settings

- Runtime: Python 3.14, Python 3.13, or Python 3.12
- Handler: `guardrail.lambda_handler`
- Timeout: start with 5 minutes
- Memory: 256 MB is usually enough

## IAM Policy

Attach this policy to the Lambda execution role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeRegions",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:ModifyDBInstance",
        "rds:ModifyDBCluster",
        "rds:DeleteDBInstance",
        "rds:DeleteDBCluster"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

## Zip And Deploy

From this directory:

```bash
zip rds-guardrail.zip guardrail.py
aws lambda create-function \
  --function-name rds-version-guardrail \
  --runtime python3.14 \
  --handler guardrail.lambda_handler \
  --role arn:aws:iam::<account-id>:role/<lambda-role-name> \
  --timeout 300 \
  --memory-size 256 \
  --zip-file fileb://rds-guardrail.zip
```

For an existing Lambda:

```bash
zip rds-guardrail.zip guardrail.py
aws lambda update-function-code \
  --function-name rds-version-guardrail \
  --zip-file fileb://rds-guardrail.zip
```

## Test Event

Report outdated resources in specific regions without deleting them:

```json
{
  "regions": ["us-east-1", "us-west-2"]
}
```

Report outdated resources in all enabled commercial regions without deleting them:

```json
{}
```

Manually test target-only deletion:

```json
{
  "targets": [
    {
      "region": "us-east-1",
      "resource_type": "DBInstance",
      "identifier": "test-db"
    }
  ]
}
```

The Lambda console test event can also use a flat target:

```json
{
  "region": "us-east-1",
  "resource_type": "DBInstance",
  "identifier": "test-db"
}
```

Tune status retries for a manual target-only test:

```json
{
  "targets": [
    {
      "region": "us-east-1",
      "resource_type": "DBInstance",
      "identifier": "test-db"
    }
  ],
  "status_retry_attempts": 20,
  "status_retry_delay_seconds": 15
}
```

## EventBridge Rule

Use a CloudTrail-backed EventBridge rule so the Lambda receives the API event that created or restored the resource:

```json
{
  "source": ["aws.rds"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["rds.amazonaws.com"],
    "eventName": [
      "CreateDBInstance",
      "CreateDBInstanceReadReplica",
      "RestoreDBInstanceFromDBSnapshot",
      "RestoreDBInstanceFromS3",
      "RestoreDBInstanceToPointInTime",
      "CreateDBCluster",
      "RestoreDBClusterFromSnapshot",
      "RestoreDBClusterToPointInTime"
    ]
  }
}
```

Do not include `ModifyDBInstance` or `ModifyDBCluster` in the rule. Those scale or configuration changes can happen to existing databases, and the Lambda intentionally ignores them when they arrive.

The Lambda identifies whether the new outdated resource is a DB instance or DB cluster, waits until the resource status is `available`, removes RDS deletion protection when it is enabled, waits for the resource to become `available` again, and requests deletion with final snapshots skipped. It does not delete existing snapshots.

The Lambda returns `PASS` when no outdated targeted resource is found or when an unsupported EventBridge event is ignored, `FAIL` when a manual report-only scan finds outdated resources, `DELETE_REQUESTED` when deletion was requested successfully, and `ERROR` when one or more describe or delete operations failed.
