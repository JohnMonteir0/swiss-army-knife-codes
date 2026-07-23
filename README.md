# swiss-army-knife-codes

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
![Repository size](https://img.shields.io/github/repo-size/johnmonteiro/swiss-army-knife-codes)
![Last commit](https://img.shields.io/github/last-commit/johnmonteiro/swiss-army-knife-codes)

Repo with versatile codes to solve different problems.

## Update a KMS key policy

Edit `POLICY_CONFIG` in `update-kms-policy.py`, replacing the example account ID
and adding the statements required by your key. The Lambda test event only needs
the target KMS key identifier:

```json
{
  "key_id": "xpto-123"
}
```

`key_id` can be a KMS key ID, key ARN, alias name, or alias ARN. The KMS
**key material ID** displayed by AWS is different and cannot be passed to the
`PutKeyPolicy` API to select a key.
