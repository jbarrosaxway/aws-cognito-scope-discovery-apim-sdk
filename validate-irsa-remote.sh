#!/bin/bash

echo "=== Validação IRSA Remota ==="
echo "Namespace: axway"
echo "Deployment: apim-digio-gateway-apitraffic"

# 1. Verificar se o AWS CLI está configurado
echo -e "\n📋 Verificando AWS CLI:"
if command -v aws &> /dev/null; then
    echo "✅ AWS CLI instalado"
    aws --version
else
    echo "❌ AWS CLI não instalado"
    exit 1
fi

# 2. Verificar credenciais AWS
echo -e "\n📋 Verificando credenciais AWS:"
aws sts get-caller-identity 2>/dev/null || {
    echo "❌ AWS CLI não configurado"
    echo "Configure com: aws configure"
    exit 1
}

# 3. Verificar se o IAM Role existe
echo -e "\n📋 Verificando IAM Role:"
ROLE_NAME="axway-lambda-role"
ACCOUNT_ID="785212834098"

if aws iam get-role --role-name "$ROLE_NAME" 2>/dev/null; then
    echo "✅ IAM Role $ROLE_NAME existe"
    
    # Verificar trust policy
    echo -e "\n📋 Trust Policy do Role:"
    aws iam get-role --role-name "$ROLE_NAME" --query 'Role.AssumeRolePolicyDocument' --output json
    
    # Verificar policies anexadas
    echo -e "\n📋 Policies anexadas:"
    aws iam list-attached-role-policies --role-name "$ROLE_NAME"
    
else
    echo "❌ IAM Role $ROLE_NAME não existe"
    echo "Crie o role primeiro"
fi

# 4. Verificar se o cluster EKS existe
echo -e "\n📋 Verificando cluster EKS:"
CLUSTER_NAME=$(aws eks list-clusters --query 'clusters[0]' --output text 2>/dev/null)
if [ "$CLUSTER_NAME" != "None" ]; then
    echo "✅ Cluster encontrado: $CLUSTER_NAME"
    
    # Verificar OIDC provider
    echo -e "\n📋 OIDC Provider:"
    aws eks describe-cluster --name "$CLUSTER_NAME" --query 'cluster.identity.oidc.issuer' --output text 2>/dev/null || echo "❌ OIDC provider não configurado"
    
else
    echo "❌ Nenhum cluster EKS encontrado"
fi

# 5. Verificar se o Lambda function existe e tem permissões
echo -e "\n📋 Verificando Lambda function:"
FUNCTION_NAME="uat-corporate-services-cpv"
REGION="sa-east-1"

if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" 2>/dev/null; then
    echo "✅ Lambda function $FUNCTION_NAME existe"
    
    # Testar invoke (apenas verificar permissões)
    echo -e "\n📋 Testando permissões Lambda:"
    aws lambda invoke \
        --function-name "$FUNCTION_NAME" \
        --payload '{"test": "permission"}' \
        --region "$REGION" \
        /tmp/test-output.json 2>/dev/null && {
        echo "✅ Permissões Lambda OK"
        rm -f /tmp/test-output.json
    } || echo "❌ Sem permissões para invocar Lambda"
    
else
    echo "❌ Lambda function $FUNCTION_NAME não existe"
fi

# 6. Verificar via logs do Axway
echo -e "\n📋 Verificação via Logs:"
echo "Para verificar se IRSA está funcionando, procure nos logs do Axway:"
echo "1. AWS_WEB_IDENTITY_TOKEN_FILE: /var/run/secrets/eks.amazonaws.com/serviceaccount/token"
echo "2. AWS_ROLE_ARN: arn:aws:iam::785212834098:role/axway-lambda-role"
echo "3. User ARN deve ser diferente de: arn:aws:sts::785212834098:assumed-role/axway-first-ng-role/..."

echo -e "\n=== Comandos para Verificar ==="
echo "# 1. Verificar logs do pod:"
echo "kubectl logs -n axway deployment/apim-digio-gateway-apitraffic | grep -i 'IRSA\\|AWS_WEB_IDENTITY\\|AWS_ROLE_ARN'"

echo -e "\n# 2. Verificar ServiceAccount:"
echo "kubectl get serviceaccount -n axway -o yaml"

echo -e "\n# 3. Verificar pod:"
echo "kubectl get pod -n axway -l app=apim-digio-gateway-apitraffic -o yaml"

echo -e "\n# 4. Verificar variáveis de ambiente:"
echo "kubectl exec -n axway deployment/apim-digio-gateway-apitraffic -- env | grep -E '(AWS_|IRSA)'"

echo -e "\n=== Indicadores de Sucesso ==="
echo "✅ IRSA funcionando se:"
echo "- AWS_WEB_IDENTITY_TOKEN_FILE está definido"
echo "- AWS_ROLE_ARN aponta para axway-lambda-role"
echo "- User ARN contém 'assumed-role/axway-lambda-role'"
echo "- Logs mostram 'IRSA Debug' com credenciais válidas"

echo -e "\n=== Indicadores de Problema ==="
echo "❌ IRSA não funcionando se:"
echo "- User ARN contém 'assumed-role/axway-first-ng-role'"
echo "- AWS_WEB_IDENTITY_TOKEN_FILE não está definido"
echo "- Erro 403 AccessDeniedException" 