# Validação IRSA Remota - PowerShell
Write-Host "=== Validação IRSA Remota ===" -ForegroundColor Cyan
Write-Host "Namespace: axway" -ForegroundColor Yellow
Write-Host "Deployment: apim-digio-gateway-apitraffic" -ForegroundColor Yellow

# 1. Verificar se o AWS CLI está configurado
Write-Host "`n📋 Verificando AWS CLI:" -ForegroundColor Green
try {
    $awsVersion = aws --version 2>$null
    if ($awsVersion) {
        Write-Host "✅ AWS CLI instalado" -ForegroundColor Green
        Write-Host $awsVersion
    } else {
        Write-Host "❌ AWS CLI não instalado" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ AWS CLI não instalado" -ForegroundColor Red
    exit 1
}

# 2. Verificar credenciais AWS
Write-Host "`n📋 Verificando credenciais AWS:" -ForegroundColor Green
try {
    $callerIdentity = aws sts get-caller-identity 2>$null | ConvertFrom-Json
    if ($callerIdentity) {
        Write-Host "✅ AWS CLI configurado" -ForegroundColor Green
        Write-Host "Account: $($callerIdentity.Account)"
        Write-Host "User: $($callerIdentity.Arn)"
    } else {
        Write-Host "❌ AWS CLI não configurado" -ForegroundColor Red
        Write-Host "Configure com: aws configure" -ForegroundColor Yellow
        exit 1
    }
} catch {
    Write-Host "❌ AWS CLI não configurado" -ForegroundColor Red
    Write-Host "Configure com: aws configure" -ForegroundColor Yellow
    exit 1
}

# 3. Verificar se o IAM Role existe
Write-Host "`n📋 Verificando IAM Role:" -ForegroundColor Green
$ROLE_NAME = "axway-lambda-role"
$ACCOUNT_ID = "785212834098"

try {
    $roleInfo = aws iam get-role --role-name $ROLE_NAME 2>$null | ConvertFrom-Json
    if ($roleInfo) {
        Write-Host "✅ IAM Role $ROLE_NAME existe" -ForegroundColor Green
        
        # Verificar trust policy
        Write-Host "`n📋 Trust Policy do Role:" -ForegroundColor Green
        $trustPolicy = aws iam get-role --role-name $ROLE_NAME --query 'Role.AssumeRolePolicyDocument' --output json 2>$null
        Write-Host $trustPolicy
        
        # Verificar policies anexadas
        Write-Host "`n📋 Policies anexadas:" -ForegroundColor Green
        $attachedPolicies = aws iam list-attached-role-policies --role-name $ROLE_NAME 2>$null
        Write-Host $attachedPolicies
        
    } else {
        Write-Host "❌ IAM Role $ROLE_NAME não existe" -ForegroundColor Red
        Write-Host "Crie o role primeiro" -ForegroundColor Yellow
    }
} catch {
    Write-Host "❌ IAM Role $ROLE_NAME não existe" -ForegroundColor Red
    Write-Host "Crie o role primeiro" -ForegroundColor Yellow
}

# 4. Verificar se o cluster EKS existe
Write-Host "`n📋 Verificando cluster EKS:" -ForegroundColor Green
try {
    $clusters = aws eks list-clusters --query 'clusters[0]' --output text 2>$null
    if ($clusters -and $clusters -ne "None") {
        Write-Host "✅ Cluster encontrado: $clusters" -ForegroundColor Green
        
        # Verificar OIDC provider
        Write-Host "`n📋 OIDC Provider:" -ForegroundColor Green
        $oidcProvider = aws eks describe-cluster --name $clusters --query 'cluster.identity.oidc.issuer' --output text 2>$null
        if ($oidcProvider) {
            Write-Host "✅ OIDC Provider: $oidcProvider" -ForegroundColor Green
        } else {
            Write-Host "❌ OIDC provider não configurado" -ForegroundColor Red
        }
        
    } else {
        Write-Host "❌ Nenhum cluster EKS encontrado" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Nenhum cluster EKS encontrado" -ForegroundColor Red
}

# 5. Verificar se o Lambda function existe e tem permissões
Write-Host "`n📋 Verificando Lambda function:" -ForegroundColor Green
$FUNCTION_NAME = "uat-corporate-services-cpv"
$REGION = "sa-east-1"

try {
    $functionInfo = aws lambda get-function --function-name $FUNCTION_NAME --region $REGION 2>$null | ConvertFrom-Json
    if ($functionInfo) {
        Write-Host "✅ Lambda function $FUNCTION_NAME existe" -ForegroundColor Green
        
        # Testar invoke (apenas verificar permissões)
        Write-Host "`n📋 Testando permissões Lambda:" -ForegroundColor Green
        $testPayload = '{"test": "permission"}'
        $testResult = aws lambda invoke --function-name $FUNCTION_NAME --payload $testPayload --region $REGION /tmp/test-output.json 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✅ Permissões Lambda OK" -ForegroundColor Green
            if (Test-Path "/tmp/test-output.json") {
                Remove-Item "/tmp/test-output.json" -Force
            }
        } else {
            Write-Host "❌ Sem permissões para invocar Lambda" -ForegroundColor Red
        }
        
    } else {
        Write-Host "❌ Lambda function $FUNCTION_NAME não existe" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ Lambda function $FUNCTION_NAME não existe" -ForegroundColor Red
}

# 6. Verificar via logs do Axway
Write-Host "`n📋 Verificação via Logs:" -ForegroundColor Green
Write-Host "Para verificar se IRSA está funcionando, procure nos logs do Axway:" -ForegroundColor Yellow
Write-Host "1. AWS_WEB_IDENTITY_TOKEN_FILE: /var/run/secrets/eks.amazonaws.com/serviceaccount/token" -ForegroundColor White
Write-Host "2. AWS_ROLE_ARN: arn:aws:iam::785212834098:role/axway-lambda-role" -ForegroundColor White
Write-Host "3. User ARN deve ser diferente de: arn:aws:sts::785212834098:assumed-role/axway-first-ng-role/..." -ForegroundColor White

Write-Host "`n=== Comandos para Verificar ===" -ForegroundColor Cyan
Write-Host "# 1. Verificar logs do pod:" -ForegroundColor Yellow
Write-Host "kubectl logs -n axway deployment/apim-digio-gateway-apitraffic | grep -i 'IRSA|AWS_WEB_IDENTITY|AWS_ROLE_ARN'" -ForegroundColor White

Write-Host "`n# 2. Verificar ServiceAccount:" -ForegroundColor Yellow
Write-Host "kubectl get serviceaccount -n axway -o yaml" -ForegroundColor White

Write-Host "`n# 3. Verificar pod:" -ForegroundColor Yellow
Write-Host "kubectl get pod -n axway -l app=apim-digio-gateway-apitraffic -o yaml" -ForegroundColor White

Write-Host "`n# 4. Verificar variáveis de ambiente:" -ForegroundColor Yellow
Write-Host "kubectl exec -n axway deployment/apim-digio-gateway-apitraffic -- env | grep -E '(AWS_|IRSA)'" -ForegroundColor White

Write-Host "`n=== Indicadores de Sucesso ===" -ForegroundColor Green
Write-Host "✅ IRSA funcionando se:" -ForegroundColor Green
Write-Host "- AWS_WEB_IDENTITY_TOKEN_FILE está definido" -ForegroundColor White
Write-Host "- AWS_ROLE_ARN aponta para axway-lambda-role" -ForegroundColor White
Write-Host "- User ARN contém 'assumed-role/axway-lambda-role'" -ForegroundColor White
Write-Host "- Logs mostram 'IRSA Debug' com credenciais válidas" -ForegroundColor White

Write-Host "`n=== Indicadores de Problema ===" -ForegroundColor Red
Write-Host "❌ IRSA não funcionando se:" -ForegroundColor Red
Write-Host "- User ARN contém 'assumed-role/axway-first-ng-role'" -ForegroundColor White
Write-Host "- AWS_WEB_IDENTITY_TOKEN_FILE não está definido" -ForegroundColor White
Write-Host "- Erro 403 AccessDeniedException" -ForegroundColor White 