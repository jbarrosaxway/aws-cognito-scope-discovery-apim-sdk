# Guia de Configuração - AWS Cognito Scope Discovery

## Problema Identificado

O erro `NullPointerException` na linha 410 está ocorrendo porque o `cognitoClient` não foi inicializado corretamente. Isso pode acontecer por várias razões:

## Possíveis Causas

### 1. **Configuração de Credenciais Incorreta**
- **Tipo de credencial**: Verifique se o campo `credentialType` está configurado corretamente
- **Valores válidos**: `"iam"`, `"file"`, ou qualquer outro valor para usar AWSFactory

### 2. **Configuração de Região**
- **Campo**: `awsRegion`
- **Valor padrão**: `"us-east-1"`
- **Problema**: Se a região estiver incorreta, a inicialização pode falhar

### 3. **Configuração de Entity**
- **Problema**: Se `entity` for `null`, a inicialização falha
- **Verificação**: Logs mostrarão "Entity é null - não é possível inicializar o cliente"

### 4. **Configuração de Context**
- **Problema**: Se `ctx` for `null`, a inicialização falha
- **Verificação**: Logs mostrarão "ConfigContext (ctx) é null - não é possível inicializar o cliente"

## Configuração Recomendada

### Para Ambiente de Desenvolvimento (IAM Role)
```json
{
  "credentialType": "iam",
  "awsRegion": "us-east-1",
  "userPoolId": "us-east-1_XXXXXXXXX",
  "clientId": "YYYYYYYYYYYYYYYYYYYYYYY"
}
```

### Para Ambiente com Credenciais de Arquivo
```json
{
  "credentialType": "file",
  "credentialsFilePath": "/path/to/credentials",
  "awsRegion": "us-east-1",
  "userPoolId": "us-east-1_XXXXXXXXX",
  "clientId": "YYYYYYYYYYYYYYYYYYYYYYY"
}
```

### Para Ambiente com Credenciais Explícitas
```json
{
  "credentialType": "explicit",
  "awsRegion": "us-east-1",
  "userPoolId": "us-east-1_XXXXXXXXX",
  "clientId": "YYYYYYYYYYYYYYYYYYYYYYY"
}
```

## Logs de Debug

Com as melhorias implementadas, você verá logs detalhados:

```
=== Inicializando Cliente Cognito ===
ConfigContext e Entity disponíveis, prosseguindo com inicialização...
ClientConfiguration criado com sucesso
=== Credentials Provider Debug ===
Credential Type Value: iam
Using IAM Role credentials - WebIdentityTokenCredentialsProvider
=== IRSA Debug ===
AWS_WEB_IDENTITY_TOKEN_FILE: /var/run/secrets/eks.amazonaws.com/serviceaccount/token
AWS_ROLE_ARN: arn:aws:iam::123456789012:role/eks-cluster-role
AWS_REGION: us-east-1
✅ Using WebIdentityTokenCredentialsProvider for IAM role
CredentialsProvider criado com sucesso
Região AWS: us-east-1
✅ Cliente Cognito inicializado com sucesso
Cliente tipo: AWSCognitoIdentityProviderClient
```

## Verificações de Ambiente

### 1. **Variáveis de Ambiente (para IAM Role)**
```bash
echo $AWS_WEB_IDENTITY_TOKEN_FILE
echo $AWS_ROLE_ARN
echo $AWS_REGION
```

### 2. **Permissões IAM**
O role deve ter as seguintes permissões:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cognito-idp:DescribeUserPoolClient",
        "cognito-idp:ListResourceServers"
      ],
      "Resource": "*"
    }
  ]
}
```

### 3. **Configuração de Rede**
- **VPC**: Verificar se a instância tem acesso à internet
- **Security Groups**: Verificar se as regras permitem tráfego HTTPS (443)
- **NAT Gateway**: Se em subnet privada, verificar se NAT Gateway está configurado

## Solução de Problemas

### 1. **Cliente não inicializa**
- Verificar logs de inicialização
- Confirmar configuração de credenciais
- Verificar permissões IAM

### 2. **Erro de autenticação**
- Verificar se as credenciais são válidas
- Confirmar se o role tem as permissões necessárias
- Verificar se a região está correta

### 3. **Erro de rede**
- Verificar conectividade com AWS
- Confirmar configuração de VPC/Security Groups
- Verificar se há proxy configurado

## Teste de Conectividade

Após a correção, você deve ver:
```
INFO: Iniciando descoberta de scopes do AWS Cognito
INFO: userPoolId: us-east-18thizhjhc, clientId: PMCI
INFO: Client encontrado: [Nome do Client]
INFO: Total de scopes descobertos para Client PMCI: X
INFO: Descoberta de scopes concluída com sucesso
```

Se ainda houver problemas, os logs detalhados ajudarão a identificar a causa específica.
