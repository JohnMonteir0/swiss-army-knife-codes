# RDS Guardrail Lambda Runbook

This Lambda scans RDS DB instances and DB clusters for engine versions below the policy in `guardrail.py`.
When it runs in Lambda, it automatically deletes outdated resources without requiring an event flag.

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

Scan specific regions:

```json
{
  "regions": ["us-east-1", "us-west-2"]
}
```

Scan all enabled commercial regions:

```json
{}
```

Delete outdated resources in specific regions:

```json
{
  "regions": ["us-east-1", "us-west-2"]
}
```

Tune status retries when EventBridge invokes the Lambda:

```json
{
  "regions": ["us-east-1", "us-west-2"],
  "status_retry_attempts": 20,
  "status_retry_delay_seconds": 15
}
```

The Lambda identifies whether each outdated resource is a DB instance or DB cluster, waits until the resource status is `available`, removes RDS deletion protection when it is enabled, waits for the resource to become `available` again, and requests deletion with final snapshots skipped. It does not delete existing snapshots.

The Lambda returns `PASS` when no outdated resources are found, `FAIL` when outdated resources are found, `DELETE_REQUESTED` when deletion was requested successfully, and `ERROR` when one or more regions or delete operations failed.
