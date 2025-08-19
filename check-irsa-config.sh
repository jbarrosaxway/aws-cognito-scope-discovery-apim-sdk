#!/bin/bash

echo "=== Verificação de Configuração IRSA ==="

# Verificar se kubectl está configurado
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl não está instalado ou configurado"
    exit 1
fi

# Verificar contexto atual
echo "📋 Contexto Kubernetes atual:"
kubectl config current-context

# Verificar ServiceAccounts
echo -e "\n📋 ServiceAccounts no cluster:"
kubectl get serviceaccounts -A

# Verificar pods do Axway
echo -e "\n📋 Pods do Axway:"
kubectl get pods -A | grep -i axway || echo "Nenhum pod do Axway encontrado"

# Verificar se o cluster tem OIDC provider configurado
echo -e "\n📋 Verificando OIDC Provider:"
kubectl get configmap -n kube-system aws-auth -o yaml 2>/dev/null | grep -i oidc || echo "OIDC provider não encontrado"

# Verificar se o pod tem as variáveis de ambiente do IRSA
echo -e "\n📋 Verificando variáveis de ambiente IRSA em pods do Axway:"
PODS=$(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\n"}{end}' | grep -i axway)

if [ -n "$PODS" ]; then
    echo "$PODS" | while read -r namespace pod; do
        echo "Pod: $namespace/$pod"
        kubectl exec -n "$namespace" "$pod" -- env | grep -E "(AWS_|IRSA)" || echo "  Nenhuma variável IRSA encontrada"
    done
else
    echo "Nenhum pod do Axway encontrado para verificar"
fi

echo -e "\n=== Configuração Necessária ==="
echo "Para usar IRSA, você precisa:"
echo "1. ✅ Configurar OIDC provider no cluster EKS"
echo "2. ✅ Criar IAM Role com trust policy para o OIDC"
echo "3. ✅ Configurar ServiceAccount com annotation eks.amazonaws.com/role-arn"
echo "4. ✅ Deploy do pod com o ServiceAccount correto"

echo -e "\n=== Exemplo de Configuração ==="
cat << 'EOF'
# 1. IAM Role Policy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:InvokeFunction",
        "lambda:GetFunction",
        "lambda:ListFunctions"
      ],
      "Resource": [
        "arn:aws:lambda:sa-east-1:785212834098:function:*"
      ]
    }
  ]
}

# 2. Trust Policy
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::785212834098:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}

# 3. ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: axway-lambda-sa
  namespace: axway
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::785212834098:role/axway-lambda-role"

# 4. Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: axway-gateway
spec:
  template:
    spec:
      serviceAccountName: axway-lambda-sa
      containers:
      - name: axway-gateway
        image: axway/gateway
EOF 