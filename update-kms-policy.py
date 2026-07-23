import json

import boto3


kms = boto3.client("kms")

# Edit the policy here before deploying the Lambda.
#
# Replace 123456789012 with your AWS account ID and add any other statements
# required by your application. Keeping this in the source means the Lambda
# invocation only needs to identify the KMS key to update.
POLICY_CONFIG = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "EnableIAMUserPermissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789012:root",
            },
            "Action": "kms:*",
            "Resource": "*",
        },
    ],
}


def lambda_handler(event, context):
    key_id = event.get("key_id")

    if not key_id:
        raise ValueError("event.key_id is required")

    policy = POLICY_CONFIG

    if policy.get("Version") != "2012-10-17":
        raise ValueError("Policy Version must be 2012-10-17")

    statements = policy.get("Statement")
    if not isinstance(statements, list) or not statements:
        raise ValueError("Policy must contain at least one Statement")

    for statement in statements:
        for required_field in ("Effect", "Principal", "Action", "Resource"):
            if required_field not in statement:
                raise ValueError(
                    f"Policy statement is missing {required_field}: "
                    f"{statement.get('Sid', '<no Sid>')}"
                )

    policy_json = json.dumps(policy)

    if len(policy_json.encode("utf-8")) > 32768:
        raise ValueError("KMS key policy exceeds the 32 KB limit")

    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=policy_json,
        BypassPolicyLockoutSafetyCheck=False,
    )

    return {
        "statusCode": 200,
        "body": {
            "message": "KMS key policy updated successfully",
            "key_id": key_id,
        },
    }
