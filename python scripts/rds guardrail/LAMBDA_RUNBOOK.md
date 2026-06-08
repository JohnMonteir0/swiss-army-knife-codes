# RDS Guardrail Lambda Runbook

This Lambda scans RDS DB instances and DB clusters for engine versions below the policy in `guardrail.py`.
When EventBridge invokes it for an RDS create or restore API event, it checks only the resource from that event and deletes it only when it violates the version policy. RDS resources that existed before the event are not deleted. Modify and scale events are ignored.

## Version Policy Exceptions

Add DB instance or DB cluster identifiers to `POLICY_EXCEPTIONS` in `guardrail.py` when a resource must be allowed to use a version below the configured minimum:

```python
POLICY_EXCEPTIONS = {
    "DBInstance": {
        "legacy-instance",
    },
    "DBCluster": {
        "legacy-cluster",
    },
}
```

Identifier matching is case-insensitive. An exempt resource is omitted from findings and is not deleted by an EventBridge-triggered creation or restore check. Keep instance and cluster exceptions in their corresponding sets.

## Lambda Settings

- Runtime: Python 3.14, Python 3.13, or Python 3.12
- Handler: `guardrail.lambda_handler`
- Timeout: use up to 15 minutes when deleting newly created RDS resources; creation can remain in states like `backing-up` for several minutes
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

Tune status wait time for a manual target-only test:

```json
{
  "targets": [
    {
      "region": "us-east-1",
      "resource_type": "DBInstance",
      "identifier": "test-db"
    }
  ],
  "status_wait_timeout_seconds": 840,
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

The Lambda identifies whether the new outdated resource is a DB instance or DB cluster, waits until the resource status is `available`, removes RDS deletion protection when it is enabled, waits for the resource to become `available` again, and requests deletion with final snapshots skipped. If a concurrent Lambda invocation already deleted the resource or deletion is already in progress, the invocation finishes without reporting an error. For DB clusters, it first deletes writer/reader member instances and waits until they are `deleting` or gone before deleting the cluster. It does not delete existing snapshots. The default wait budget is 840 seconds, and Lambda caps that value to the current invocation's remaining time with a 20 second buffer.

The Lambda returns `PASS` when no outdated targeted resource is found or when an unsupported EventBridge event is ignored, `FAIL` when a manual report-only scan finds outdated resources, `DELETE_REQUESTED` when deletion was requested successfully, and `ERROR` when one or more describe or delete operations failed.
