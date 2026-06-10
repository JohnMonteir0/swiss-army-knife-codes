# RDS Guardrail Lambda Runbook

This Lambda scans RDS DB instances and DB clusters for engine versions below the policy in `guardrail.py`.
When EventBridge invokes it for an RDS create or restore API event, it checks only the resource from that event and deletes it only when it violates the version policy. RDS resources that existed before the event are not deleted. Modify and scale events are ignored.

## S3 Policy Configuration

The Lambda loads both policies from S3 before every scan. It does not contain fallback policy values, so a missing, inaccessible, or invalid object returns `ERROR` and prevents deletion.

Upload JSON based on these repository templates:

- `policy.example.json`: engine minimum versions and messages
- `policy-exceptions.example.json`: global and account-specific resource exceptions

Configure these Lambda environment variables:

| Variable | Required | Description |
| --- | --- | --- |
| `POLICY_BUCKET` | Yes | Bucket containing both JSON objects |
| `POLICY_KEY` | Yes | Version policy object key, for example `rds/policy.json` |
| `POLICY_EXCEPTIONS_KEY` | Yes | Exceptions object key, for example `rds/policy-exceptions.json` |
| `POLICY_BUCKET_REGION` | No | Bucket region; recommended when it differs from the Lambda region |
| `POLICY_CONFIG_ROLE_ARN` | No | Cross-account role to assume before reading the objects |

Exception identifier strings apply in every account. A two-value JSON array applies only when both the account ID and identifier match:

```json
{
  "DBInstance": [
    "legacy-instance",
    ["123456789012", "account-specific-instance"]
  ],
  "DBCluster": []
}
```

Identifier matching is case-insensitive; account IDs must match exactly. An exempt outdated resource is omitted from findings, is not deleted, and appears under `exceptions` with `result` set to `EXCEPTION`.

Exceptions are inherited through RDS relationships, without depending on generated naming conventions:

- Every DB instance whose `DBClusterIdentifier` points to an exempt cluster inherits that cluster exception. This protects existing members and members added later through scaling.
- A read replica whose `ReadReplicaSourceDBInstanceIdentifier` points to an exempt DB instance inherits the source exception, including cross-region replica ARNs.
- Account-scoped exceptions are inherited only when the parent cluster or source instance account ID also matches.

The output includes `exception_match.match_type` as `DIRECT`, `PARENT_CLUSTER`, or `SOURCE_INSTANCE`, plus the identifier that supplied the exception.

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
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": [
        "arn:aws:s3:::<policy-bucket>/rds/policy.json",
        "arn:aws:s3:::<policy-bucket>/rds/policy-exceptions.json"
      ]
    }
  ]
}
```

For direct cross-account access, also add this policy to the bucket in the policy account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowRdsGuardrailPolicyRead",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<lambda-account-id>:role/<lambda-role-name>"
      },
      "Action": "s3:GetObject",
      "Resource": [
        "arn:aws:s3:::<policy-bucket>/rds/policy.json",
        "arn:aws:s3:::<policy-bucket>/rds/policy-exceptions.json"
      ]
    }
  ]
}
```

Alternatively, set `POLICY_CONFIG_ROLE_ARN` to a role in the policy account. Allow the Lambda role to call `sts:AssumeRole`, configure that role's trust policy for the Lambda role, and grant the assumed role `s3:GetObject` on both objects. If the objects use a customer-managed KMS key, also grant `kms:Decrypt` in IAM and the KMS key policy.

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
  --environment 'Variables={POLICY_BUCKET=<policy-bucket>,POLICY_KEY=rds/policy.json,POLICY_EXCEPTIONS_KEY=rds/policy-exceptions.json,POLICY_BUCKET_REGION=us-east-1}' \
  --zip-file fileb://rds-guardrail.zip
```

For an existing Lambda:

```bash
zip rds-guardrail.zip guardrail.py
aws lambda update-function-code \
  --function-name rds-version-guardrail \
  --zip-file fileb://rds-guardrail.zip
```

Update environment variables separately when needed:

```bash
aws lambda update-function-configuration \
  --function-name rds-version-guardrail \
  --environment 'Variables={POLICY_BUCKET=<policy-bucket>,POLICY_KEY=rds/policy.json,POLICY_EXCEPTIONS_KEY=rds/policy-exceptions.json,POLICY_BUCKET_REGION=us-east-1}'
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

The Lambda returns `PASS` when no outdated targeted resource is found, when an outdated resource matches a policy exception, or when an unsupported EventBridge event is ignored. It returns `FAIL` when a manual report-only scan finds outdated resources, `DELETE_REQUESTED` when deletion was requested successfully, and `ERROR` when one or more describe or delete operations failed.
