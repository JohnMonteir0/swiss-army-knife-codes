# Runbook da Lambda de Guardrail do RDS

Esta Lambda verifica instancias de banco de dados e clusters do RDS que utilizam versoes de engine abaixo da politica definida em `guardrail.py`.
Quando o EventBridge a invoca para um evento de API de criacao ou restauracao do RDS, ela verifica somente o recurso desse evento e o exclui apenas quando ele viola a politica de versao. Recursos do RDS que ja existiam antes do evento nao sao excluidos. Eventos de modificacao e escalabilidade sao ignorados.

## Configuracao das Politicas no S3

A Lambda carrega as duas politicas do S3 antes de cada verificacao. Ela nao possui valores de politica alternativos no codigo. Portanto, um objeto ausente, inacessivel ou invalido retorna `ERROR` e impede a exclusao.

Envie arquivos JSON baseados nestes modelos do repositorio:

- `policy.example.json`: versoes minimas e mensagens para cada engine
- `policy-exceptions.example.json`: excecoes de recursos globais e especificas por conta

Configure estas variaveis de ambiente na Lambda:

| Variavel | Obrigatoria | Descricao |
| --- | --- | --- |
| `POLICY_BUCKET` | Sim | Bucket que contem os dois objetos JSON |
| `POLICY_KEY` | Sim | Chave do objeto da politica de versao, por exemplo `rds/policy.json` |
| `POLICY_EXCEPTIONS_KEY` | Sim | Chave do objeto de excecoes, por exemplo `rds/policy-exceptions.json` |
| `POLICY_BUCKET_REGION` | Nao | Regiao do bucket; recomendada quando for diferente da regiao da Lambda |
| `POLICY_CONFIG_ROLE_ARN` | Nao | Role entre contas que deve ser assumida antes da leitura dos objetos |

Identificadores de excecao definidos como strings sao aplicados a todas as contas. Um array JSON com dois valores e aplicado somente quando o ID da conta e o identificador correspondem:

```json
{
  "DBInstance": [
    "legacy-instance",
    ["123456789012", "account-specific-instance"]
  ],
  "DBCluster": []
}
```

A comparacao dos identificadores nao diferencia maiusculas de minusculas; os IDs das contas devem corresponder exatamente. Um recurso desatualizado, mas isento, e omitido dos achados, nao e excluido e aparece em `exceptions` com `result` definido como `EXCEPTION`.

As excecoes sao herdadas por meio dos relacionamentos do RDS, sem depender das convencoes de nomes gerados:

- Toda instancia de banco de dados cujo `DBClusterIdentifier` aponta para um cluster isento herda a excecao desse cluster. Isso protege os membros existentes e os membros adicionados posteriormente por escalabilidade.
- Uma replica de leitura cujo `ReadReplicaSourceDBInstanceIdentifier` aponta para uma instancia de banco de dados isenta herda a excecao da instancia de origem, inclusive quando o valor e um ARN de replica entre regioes.
- Excecoes especificas por conta sao herdadas somente quando o ID da conta do cluster pai ou da instancia de origem tambem corresponde.

A saida inclui `exception_match.match_type` como `DIRECT`, `PARENT_CLUSTER` ou `SOURCE_INSTANCE`, alem do identificador que forneceu a excecao.

## Configuracoes da Lambda

- Runtime: Python 3.14, Python 3.13 ou Python 3.12
- Handler: `guardrail.lambda_handler`
- Timeout: use ate 15 minutos ao excluir recursos do RDS recem-criados; a criacao pode permanecer por varios minutos em estados como `backing-up`
- Memoria: 256 MB normalmente sao suficientes

## Politica do IAM

Anexe esta politica a role de execucao da Lambda:

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

Para acesso direto entre contas, adicione tambem esta politica ao bucket da conta que armazena as politicas:

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

Como alternativa, defina `POLICY_CONFIG_ROLE_ARN` com uma role da conta que armazena as politicas. Permita que a role da Lambda execute `sts:AssumeRole`, configure a politica de confianca da role de destino para aceitar a role da Lambda e conceda a role assumida a permissao `s3:GetObject` nos dois objetos. Se os objetos usarem uma chave KMS gerenciada pelo cliente, conceda tambem `kms:Decrypt` no IAM e na politica da chave KMS.

## Compactacao e Implantacao

A partir deste diretorio:

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

Para uma Lambda existente:

```bash
zip rds-guardrail.zip guardrail.py
aws lambda update-function-code \
  --function-name rds-version-guardrail \
  --zip-file fileb://rds-guardrail.zip
```

Atualize as variaveis de ambiente separadamente quando necessario:

```bash
aws lambda update-function-configuration \
  --function-name rds-version-guardrail \
  --environment 'Variables={POLICY_BUCKET=<policy-bucket>,POLICY_KEY=rds/policy.json,POLICY_EXCEPTIONS_KEY=rds/policy-exceptions.json,POLICY_BUCKET_REGION=us-east-1}'
```

## Evento de Teste

Relate recursos desatualizados em regioes especificas sem exclui-los:

```json
{
  "regions": ["us-east-1", "us-west-2"]
}
```

Relate recursos desatualizados em todas as regioes comerciais habilitadas sem exclui-los:

```json
{}
```

Teste manualmente a exclusao somente dos recursos de destino:

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

O evento de teste do console da Lambda tambem pode usar um destino sem a lista `targets`:

```json
{
  "region": "us-east-1",
  "resource_type": "DBInstance",
  "identifier": "test-db"
}
```

Ajuste o tempo de espera do status em um teste manual de um recurso de destino:

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

## Regra do EventBridge

Use uma regra do EventBridge baseada no CloudTrail para que a Lambda receba o evento de API que criou ou restaurou o recurso:

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

Nao inclua `ModifyDBInstance` ou `ModifyDBCluster` na regra. Essas alteracoes de escalabilidade ou configuracao podem ocorrer em bancos de dados existentes, e a Lambda as ignora intencionalmente quando sao recebidas.

A Lambda identifica se o novo recurso desatualizado e uma instancia de banco de dados ou um cluster, aguarda ate que o status seja `available`, remove a protecao contra exclusao do RDS quando ela esta habilitada, aguarda novamente o status `available` e solicita a exclusao sem criar snapshots finais. Se outra invocacao simultanea da Lambda ja tiver excluido o recurso ou se a exclusao ja estiver em andamento, a invocacao termina sem relatar erro. Para clusters de banco de dados, ela primeiro exclui as instancias membros de escrita e leitura e aguarda ate que estejam no estado `deleting` ou nao sejam mais encontradas antes de excluir o cluster. Ela nao exclui snapshots existentes. O tempo de espera padrao e de 840 segundos, e a Lambda limita esse valor ao tempo restante da invocacao, mantendo uma margem de 20 segundos.

A Lambda retorna `PASS` quando nenhum recurso de destino desatualizado e encontrado, quando um recurso desatualizado corresponde a uma excecao da politica ou quando um evento nao suportado do EventBridge e ignorado. Ela retorna `FAIL` quando uma verificacao manual, sem exclusao, encontra recursos desatualizados; `DELETE_REQUESTED` quando a exclusao e solicitada com sucesso; e `ERROR` quando uma ou mais operacoes de descricao ou exclusao falham.
