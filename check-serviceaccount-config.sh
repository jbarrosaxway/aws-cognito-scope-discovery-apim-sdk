#!/bin/bash

echo "=== Verificação de Configuração do ServiceAccount ==="
echo "Namespace: axway"
echo "Deployment: apim-digio-gateway-apitraffic"

echo -e "\n📋 Verificando ServiceAccount:"
kubectl get serviceaccount -n axway -o yaml

echo -e "\n📋 Verificando Pod:"
kubectl get pod -n axway -l app=apim-digio-gateway-apitraffic -o yaml | grep -A 10 -B 5 "serviceAccountName"

echo -e "\n📋 Verificando variáveis de ambiente IRSA:"
kubectl exec -n axway deployment/apim-digio-gateway-apitraffic -- env | grep -E "(AWS_WEB_IDENTITY|AWS_ROLE_ARN)"

echo -e "\n📋 Verificando se o token IRSA existe:"
kubectl exec -n axway deployment/apim-digio-gateway-apitraffic -- ls -la /var/run/secrets/eks.amazonaws.com/ 2>/dev/null || echo "❌ Token IRSA não encontrado"

echo -e "\n📋 Verificando conteúdo do token (primeiras linhas):"
kubectl exec -n axway deployment/apim-digio-gateway-apitraffic -- head -5 /var/run/secrets/eks.amazonaws.com/serviceaccount/token 2>/dev/null || echo "❌ Token não encontrado"

echo -e "\n📋 Verificando logs do Axway para IRSA:"
kubectl logs -n axway deployment/apim-digio-gateway-apitraffic --tail=50 | grep -i "IRSA\|AWS_WEB_IDENTITY\|AWS_ROLE_ARN"

echo -e "\n=== Configuração Esperada ==="
echo "ServiceAccount deve ter:"
echo "  annotations:"
echo "    eks.amazonaws.com/role-arn: arn:aws:iam::785212834098:role/axway-lambda-role"

echo -e "\nPod deve ter:"
echo "  serviceAccountName: axway-lambda-sa"

echo -e "\nVariáveis de ambiente devem ter:"
echo "  AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/eks.amazonaws.com/serviceaccount/token"
echo "  AWS_ROLE_ARN=arn:aws:iam::785212834098:role/axway-lambda-role"

echo -e "\n=== Comandos para Corrigir ==="
echo "# 1. Criar ServiceAccount com IRSA:"
echo "kubectl apply -f - <<EOF"
echo "apiVersion: v1"
echo "kind: ServiceAccount"
echo "metadata:"
echo "  name: axway-lambda-sa"
echo "  namespace: axway"
echo "  annotations:"
echo "    eks.amazonaws.com/role-arn: arn:aws:iam::785212834098:role/axway-lambda-role"
echo "EOF"

echo -e "\n# 2. Atualizar Deployment:"
echo "kubectl patch deployment apim-digio-gateway-apitraffic -n axway -p '{\"spec\":{\"template\":{\"spec\":{\"serviceAccountName\":\"axway-lambda-sa\"}}}}'"

echo -e "\n# 3. Redeploy:"
echo "kubectl rollout restart deployment apim-digio-gateway-apitraffic -n axway" 