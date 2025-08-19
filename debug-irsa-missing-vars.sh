#!/bin/bash

echo "🔍 IRSA Debug - Investigando Variáveis de Ambiente Ausentes"
echo "============================================================"
echo

# Solicitar informações do usuário
echo "📋 Informações necessárias:"
read -p "Namespace do Axway: " NAMESPACE
read -p "Nome do pod Axway (ou parte do nome): " POD_NAME_PATTERN

echo
echo "🔍 1. Verificando ServiceAccount do pod..."
echo "============================================"

# Encontrar o pod
POD_NAME=$(kubectl get pods -n $NAMESPACE | grep $POD_NAME_PATTERN | head -1 | awk '{print $1}')

if [ -z "$POD_NAME" ]; then
    echo "❌ Pod não encontrado com padrão: $POD_NAME_PATTERN"
    echo "📋 Pods disponíveis no namespace $NAMESPACE:"
    kubectl get pods -n $NAMESPACE
    exit 1
fi

echo "✅ Pod encontrado: $POD_NAME"

# Verificar ServiceAccount do pod
echo
echo "🔍 2. ServiceAccount usado pelo pod:"
SERVICE_ACCOUNT=$(kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.spec.serviceAccountName}')
echo "ServiceAccount: ${SERVICE_ACCOUNT:-default}"

# Verificar anotações do ServiceAccount
echo
echo "🔍 3. Anotações do ServiceAccount:"
echo "=================================="
kubectl get serviceaccount ${SERVICE_ACCOUNT:-default} -n $NAMESPACE -o yaml | grep -A 10 "annotations:"

# Verificar se o Role ARN está anotado
ROLE_ARN=$(kubectl get serviceaccount ${SERVICE_ACCOUNT:-default} -n $NAMESPACE -o jsonpath='{.metadata.annotations.eks\.amazonaws\.com/role-arn}')
echo
echo "🎯 Role ARN anotado: ${ROLE_ARN:-❌ NÃO ENCONTRADO}"

# Verificar variáveis de ambiente do pod
echo
echo "🔍 4. Variáveis de ambiente IRSA no pod:"
echo "========================================"
echo "Executando: kubectl exec $POD_NAME -n $NAMESPACE -- env | grep AWS"
kubectl exec $POD_NAME -n $NAMESPACE -- env | grep AWS || echo "❌ Nenhuma variável AWS encontrada"

# Verificar se o webhook de mutação está funcionando
echo
echo "🔍 5. Verificando webhook de mutação IRSA:"
echo "=========================================="
echo "Volumes montados no pod:"
kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.spec.volumes[*].name}' | tr ' ' '\n' | grep -E "(aws|token)" || echo "❌ Nenhum volume AWS/token encontrado"

echo
echo "Mounts do container:"
kubectl get pod $POD_NAME -n $NAMESPACE -o jsonpath='{.spec.containers[0].volumeMounts[*].mountPath}' | tr ' ' '\n' | grep -E "(aws|token)" || echo "❌ Nenhum mount AWS/token encontrado"

# Verificar se o EKS Pod Identity Webhook está instalado
echo
echo "🔍 6. Verificando webhook EKS IRSA:"
echo "==================================="
kubectl get mutatingwebhookconfigurations | grep -E "(irsa|eks|pod-identity)" || echo "❌ Webhook IRSA não encontrado"

# Verificar logs recentes do pod
echo
echo "🔍 7. Logs recentes do pod (últimas 10 linhas):"
echo "==============================================="
kubectl logs $POD_NAME -n $NAMESPACE --tail=10 | grep -E "(AWS|IRSA|identity|token)" || echo "❌ Nenhum log AWS/IRSA encontrado"

echo
echo "📋 Resumo do Diagnóstico:"
echo "========================"
echo "Pod: $POD_NAME"
echo "Namespace: $NAMESPACE" 
echo "ServiceAccount: ${SERVICE_ACCOUNT:-default}"
echo "Role ARN: ${ROLE_ARN:-❌ NÃO CONFIGURADO}"
echo
echo "📝 Próximos Passos:"
echo "==================="

if [ -z "$ROLE_ARN" ]; then
    echo "1. ❌ PROBLEMA: ServiceAccount não tem anotação eks.amazonaws.com/role-arn"
    echo "   Solução: kubectl annotate serviceaccount ${SERVICE_ACCOUNT:-default} -n $NAMESPACE eks.amazonaws.com/role-arn=arn:aws:iam::ACCOUNT:role/ROLE-NAME"
    echo
    echo "2. 🔄 Reiniciar o pod após anotar o ServiceAccount"
    echo "   kubectl delete pod $POD_NAME -n $NAMESPACE"
    echo
else
    echo "1. ✅ ServiceAccount configurado com Role ARN"
    echo "2. ❌ PROBLEMA: Webhook de mutação não está injetando as variáveis"
    echo "   Verificar se o EKS IRSA webhook está funcionando"
    echo
fi

echo "3. 📖 Verificar documentação IRSA:"
echo "   https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html"