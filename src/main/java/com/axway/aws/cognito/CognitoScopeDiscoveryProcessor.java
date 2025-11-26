package com.axway.aws.cognito;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.Protocol;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.PropertiesFileCredentialsProvider;
import com.amazonaws.auth.WebIdentityTokenCredentialsProvider;
import com.vordel.circuit.aws.AWSFactory;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientRequest;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientResult;
import com.amazonaws.services.cognitoidp.model.ListResourceServersRequest;
import com.amazonaws.services.cognitoidp.model.ListResourceServersResult;
import com.amazonaws.services.cognitoidp.model.ResourceServerType;
import com.amazonaws.services.cognitoidp.model.ResourceServerScopeType;
import com.amazonaws.services.cognitoidp.model.UserPoolClientType;
import com.vordel.circuit.CircuitAbortException;
import com.vordel.circuit.Message;
import com.vordel.circuit.MessageProcessor;
import com.vordel.circuit.aws.AWSFactory;
import com.vordel.config.Circuit;
import com.vordel.config.ConfigContext;
import com.vordel.el.Selector;
import com.vordel.es.Entity;
import com.vordel.es.EntityStoreException;
import com.vordel.trace.Trace;


/**
 * Processador para descoberta dinâmica de scopes do AWS Cognito
 * 
 * Esta classe consulta o Cognito para descobrir automaticamente quais scopes
 * estão disponíveis para um determinado clientId, eliminando a necessidade
 * de mapeamentos fixos de scopes.
 */
public class CognitoScopeDiscoveryProcessor extends MessageProcessor {

    // Selectors for dynamic field resolution (following Lambda pattern) - Lazy initialization
    private Selector<String> userPoolId;
    private Selector<String> clientId;
    private Selector<String> awsRegion;
    private Selector<String> credentialType;
    private Selector<String> awsCredential;
    private Selector<String> clientConfiguration;
    private Selector<String> credentialsFilePath;
    private Selector<String> scopesInput;

    // Cliente Cognito
    private AWSCognitoIdentityProvider cognitoClient;
    
    // Última região usada para inicializar o cliente
    private String lastUsedRegion;
    
    // Context and Entity for credentials
    private ConfigContext ctx;
    private Entity entity;
    
    // Cache para scopes descobertos (userPoolId + clientId -> CacheEntry)
    private static final Map<String, CacheEntry> scopeCache = new ConcurrentHashMap<>();
    private static final long CACHE_EXPIRATION_MS = 30 * 60 * 1000; // 30 minutos

    private static class CacheEntry {
        private final Map<String, String> scopePrefixes;
        private final long timestamp;

        public CacheEntry(Map<String, String> scopePrefixes) {
            this.scopePrefixes = scopePrefixes;
            this.timestamp = System.currentTimeMillis();
        }

        public Map<String, String> getScopePrefixes() { return scopePrefixes; }
        public long getTimestamp() { return timestamp; }
        public boolean isExpired() { return System.currentTimeMillis() - timestamp > CACHE_EXPIRATION_MS; }
        public java.time.Instant getLastUpdated() { return java.time.Instant.ofEpochMilli(timestamp); }
    }

    public CognitoScopeDiscoveryProcessor() {
    }

    @Override
    public void filterAttached(ConfigContext ctx, Entity entity) throws EntityStoreException {
        super.filterAttached(ctx, entity);
        
        // Store context and entity for credentials
        this.ctx = ctx;
        this.entity = entity;
        
        // Selectors serão inicializados lazy quando necessário
        
        // Initialize Cognito client (será inicializado com região padrão, reinicializado no invoke se necessário)
        initializeCognitoClientWithDefaultRegion();
    }

    @Override
    public boolean invoke(Circuit circuit, Message message) throws CircuitAbortException {
        try {
            // Get values from selectors using lazy initialization
            String userPoolIdValue = getUserPoolId().substitute(message);
            String clientIdValue = getClientId().substitute(message);
            String scopesInputValue = getScopesInput().substitute(message);
            
            // Debug: comparar valores raw do entity
            String rawUserPoolId = entity.getStringValue("userPoolId");
            String rawRegion = entity.getStringValue("awsRegion");
            Trace.info("🔍 DEBUG - raw userPoolId: " + rawUserPoolId);
            Trace.info("🔍 DEBUG - raw awsRegion: " + rawRegion);
            
            String regionValue = getRegion(message);
            
            // Log essencial apenas
            Trace.info("Iniciando descoberta de scopes - userPoolId: " + userPoolIdValue + ", clientId: " + clientIdValue + ", região: " + regionValue);
            
            if (userPoolIdValue == null || userPoolIdValue.trim().isEmpty()) {
                throw new IllegalArgumentException("userPoolId é obrigatório");
            }
            
            if (clientIdValue == null || clientIdValue.trim().isEmpty()) {
                throw new IllegalArgumentException("clientId é obrigatório");
            }

            // Verificar se o cliente Cognito precisa ser inicializado ou reinicializado
            boolean needReinit = false;
            
            if (cognitoClient == null) {
                Trace.info("Cliente Cognito não inicializado, inicializando com região: " + regionValue);
                needReinit = true;
            } else if (!regionValue.equals(lastUsedRegion)) {
                Trace.info("⚠️ Mudança de região detectada! Última: " + lastUsedRegion + ", Nova: " + regionValue);
                Trace.info("Reinicializando cliente Cognito com nova região");
                needReinit = true;
            }
            
            if (needReinit) {
                initializeCognitoClient(regionValue);
                
                // Verificar novamente após tentativa de reinicialização
                if (cognitoClient == null) {
                    throw new Exception("Não foi possível inicializar o cliente Cognito. Verifique as configurações de credenciais e região.");
                }
                
                lastUsedRegion = regionValue;
                Trace.info("✅ Cliente Cognito inicializado/reinicializado com sucesso para região: " + regionValue);
            }

            // Discover scopes from Cognito
            Map<String, String> scopePrefixes = discoverScopesFromCognito(userPoolIdValue, clientIdValue);
            
            // Process input scopes if provided
            String processedScopes = "";
            String mappedScopes = "";
            if (scopesInputValue != null && !scopesInputValue.trim().isEmpty()) {
                processedScopes = processInputScopes(scopesInputValue);
                mappedScopes = mapInputScopes(scopesInputValue, scopePrefixes);
                
                message.put("cognito.scopes.input_processed", processedScopes);
                message.put("cognito.scopes.input_mapped", mappedScopes);
                
                Trace.info("Scopes de entrada processados: " + processedScopes);
                Trace.info("Scopes de entrada mapeados: " + mappedScopes);
            }

            // Set output properties
            message.put("cognito.scopes.available", String.join(", ", scopePrefixes.keySet()));
            message.put("cognito.scopes.mapped", String.join(", ", scopePrefixes.values()));
            message.put("cognito.scopes.prefixes", String.join(", ", scopePrefixes.keySet()));
            message.put("cognito.scopes.count", scopePrefixes.size());
            message.put("cognito.scopes.input_processed", processedScopes);
            message.put("cognito.scopes.input_mapped", mappedScopes);
            message.put("cognito.scopes.cache_hit", false);
            message.put("cognito.scopes.last_updated", java.time.Instant.now().toString());

            // Adicionar propriedades do userPoolId
            String userPoolIdSlug = generateUserPoolIdSlug(userPoolIdValue);
            message.put("cognito.user_pool_id.original", userPoolIdValue);
            message.put("cognito.user_pool_id.slug", userPoolIdSlug);
            message.put("cognito.user_pool_id.url", "https://" + userPoolIdSlug + ".auth." + regionValue + ".amazoncognito.com/oauth2/token");

            Trace.info("Descoberta de scopes concluída com sucesso");
            return true;

        } catch (Exception e) {
            Trace.error("Erro na descoberta de scopes: " + e.getMessage());
            
            // Verificar se é um erro de scope inválido
            if (e.getMessage() != null && e.getMessage().startsWith("invalid_scope")) {
                message.put("cognito.scopes.error", "invalid_scope");
                message.put("cognito.scopes.error_description", e.getMessage());
                Trace.error("Scope inválido detectado, retornando false: " + e.getMessage());
                return false; // Retorna false ao invés de lançar exceção
            } else {
                // Outros erros continuam lançando exceção
                message.put("cognito.scopes.error", "scope_discovery_failed");
                message.put("cognito.scopes.error_description", e.getMessage());
                throw new CircuitAbortException("Erro na descoberta de scopes: " + e.getMessage(), e);
            }
        }
    }

    /**
     * Inicializa o cliente Cognito com região padrão (usado no filterAttached)
     */
    private void initializeCognitoClientWithDefaultRegion() {
        try {
            Trace.info("⚙️ Tentando inicialização do cliente Cognito com região padrão...");
            
            // Tentar criar configurações de forma segura
            ClientConfiguration clientConfig = createClientConfigurationSafe();
            AWSCredentialsProvider credentialsProvider = createCredentialsProviderSafe();

            if (credentialsProvider == null) {
                Trace.info("⚠️ Não foi possível criar credenciais durante filterAttached (normal se usar expressões EL)");
                Trace.info("⚠️ Cliente será inicializado durante o primeiro invoke");
                this.cognitoClient = null;
                return;
            }

            // Validar credenciais antes de prosseguir
            try {
                AWSCredentials testCredentials = credentialsProvider.getCredentials();
                if (testCredentials == null) {
                    throw new Exception("Credenciais AWS são null");
                }
                Trace.info("✅ Credenciais AWS validadas durante inicialização");
            } catch (Exception credError) {
                Trace.info("⚠️ Validação de credenciais falhou durante filterAttached: " + credError.getMessage());
                Trace.info("⚠️ Cliente será inicializado durante o primeiro invoke");
                this.cognitoClient = null;
                return; // Não continua se não conseguir validar credenciais
            }

            this.cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                    .withCredentials(credentialsProvider)
                    .withRegion("us-east-1") // Região padrão
                    .withClientConfiguration(clientConfig)
                    .build();

            this.lastUsedRegion = "us-east-1"; // Registrar região usada
            
            Trace.info("✅ Cliente Cognito inicializado com região padrão durante filterAttached");

        } catch (Exception e) {
            String errorType = e.getClass().getSimpleName();
            Trace.info("⚠️ Erro esperado durante filterAttached (" + errorType + "): " + e.getMessage());
            Trace.info("⚠️ Cliente será inicializado durante o primeiro invoke com configurações completas");
            
            // Não logar como erro se for durante filterAttached - é esperado se houver EL expressions
            this.cognitoClient = null; // Será reinicializado no invoke com a região correta
        }
    }

    /**
     * Inicializa o cliente Cognito
     */
    private void initializeCognitoClient(String region) {
        try {
            Trace.info("Inicializando cliente Cognito - Região: " + region);
            
            ClientConfiguration clientConfig = createClientConfiguration(ctx, entity);
            AWSCredentialsProvider credentialsProvider = createCredentialsProvider(ctx, entity);

            // Tentar validar credenciais antes de criar o cliente
            try {
                AWSCredentials testCredentials = credentialsProvider.getCredentials();
                if (testCredentials != null) {
                    Trace.info("✅ Credenciais AWS obtidas com sucesso");
                } else {
                    Trace.error("❌ Credenciais AWS são null");
                }
            } catch (Exception credError) {
                Trace.error("❌ Erro ao obter credenciais AWS: " + credError.getMessage());
                throw new Exception("Falha na validação de credenciais: " + credError.getMessage(), credError);
            }

            this.cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                    .withCredentials(credentialsProvider)
                    .withRegion(region)
                    .withClientConfiguration(clientConfig)
                    .build();

            Trace.info("✅ Cliente Cognito inicializado com sucesso");

        } catch (Exception e) {
            String errorMsg = e.getMessage();
            String errorType = e.getClass().getSimpleName();
            
            Trace.error("❌ Erro ao inicializar cliente Cognito (" + errorType + "): " + errorMsg);
            
            // Diagnóstico específico
            if (errorMsg != null) {
                if (errorMsg.contains("Unable to load credentials")) {
                    Trace.error("💡 DIAGNÓSTICO: Problema com credenciais AWS. Verifique:");
                    Trace.error("   - Se está usando IAM role: AWS_ROLE_ARN e AWS_WEB_IDENTITY_TOKEN_FILE");
                    Trace.error("   - Se está usando arquivo: credentialsFilePath deve apontar para arquivo válido");
                    Trace.error("   - Se está usando credenciais explícitas: awsCredential deve estar configurado");
                } else if (errorMsg.contains("region")) {
                    Trace.error("💡 DIAGNÓSTICO: Problema com região AWS. Verifique se '" + region + "' é uma região válida");
                } else if (errorMsg.contains("NoClassDefFoundError") || errorMsg.contains("ClassNotFoundException")) {
                    Trace.error("💡 DIAGNÓSTICO: Problema de dependência. Verifique se o AWS SDK está no classpath");
                }
            }
            
            e.printStackTrace();
            this.cognitoClient = null;
        }
    }

    /**
     * Creates AWSCredentialsProvider (following Lambda pattern exactly)
     */
    private AWSCredentialsProvider createCredentialsProvider(ConfigContext ctx, Entity entity) throws Exception {
        String credentialTypeValue = getCredentialTypeSafe();
        
        Trace.info("🔑 Configurando credenciais AWS - Tipo: " + credentialTypeValue);
        
        if ("iam".equals(credentialTypeValue)) {
            // Use IAM Role - WebIdentityTokenCredentialsProvider only
            Trace.info("🔑 Usando IAM Role (IRSA)");
            
            // Debug das variáveis de ambiente
            String tokenFile = System.getenv("AWS_WEB_IDENTITY_TOKEN_FILE");
            String roleArn = System.getenv("AWS_ROLE_ARN");
            String awsRegion = System.getenv("AWS_REGION");
            
            Trace.info("🔍 AWS_WEB_IDENTITY_TOKEN_FILE: " + (tokenFile != null ? "✅ Configurado" : "❌ Não configurado"));
            Trace.info("🔍 AWS_ROLE_ARN: " + (roleArn != null ? "✅ Configurado" : "❌ Não configurado"));
            Trace.info("🔍 AWS_REGION: " + (awsRegion != null ? awsRegion : "❌ Não configurado"));
            
            if (tokenFile == null || roleArn == null) {
                throw new Exception("IAM Role mal configurado. Necessário: AWS_WEB_IDENTITY_TOKEN_FILE e AWS_ROLE_ARN");
            }
            
            return new WebIdentityTokenCredentialsProvider();
            
        } else if ("file".equals(credentialTypeValue)) {
            // Use credentials file
            String filePath = getCredentialsFilePathSafe();
            
            Trace.info("🔑 Usando arquivo de credenciais: " + filePath);
            
            if (filePath != null && !filePath.trim().isEmpty()) {
                try {
                    java.io.File credFile = new java.io.File(filePath);
                    if (!credFile.exists()) {
                        throw new Exception("Arquivo de credenciais não encontrado: " + filePath);
                    }
                    if (!credFile.canRead()) {
                        throw new Exception("Arquivo de credenciais não pode ser lido: " + filePath);
                    }
                    
                    Trace.info("✅ Arquivo de credenciais válido: " + filePath);
                    return new PropertiesFileCredentialsProvider(filePath);
                } catch (Exception e) {
                    Trace.error("❌ Erro ao carregar arquivo de credenciais: " + e.getMessage());
                    Trace.info("🔄 Usando DefaultAWSCredentialsProviderChain como fallback");
                    return new DefaultAWSCredentialsProviderChain();
                }
            } else {
                Trace.info("🔄 Caminho do arquivo não especificado, usando DefaultAWSCredentialsProviderChain");
                return new DefaultAWSCredentialsProviderChain();
            }
        } else {
            // Use explicit credentials via AWSFactory (following Lambda pattern exactly)
            Trace.info("🔑 Usando credenciais explícitas via AWSFactory");
            try {
                AWSCredentials awsCredentials = AWSFactory.getCredentials(ctx, entity);
                if (awsCredentials == null) {
                    throw new Exception("AWSFactory.getCredentials() retornou null");
                }
                Trace.info("✅ Credenciais explícitas obtidas com sucesso");
                return getAWSCredentialsProvider(awsCredentials);
            } catch (Exception e) {
                Trace.error("❌ Erro ao obter credenciais explícitas: " + e.getMessage());
                Trace.info("🔄 Usando DefaultAWSCredentialsProviderChain como fallback");
                return new DefaultAWSCredentialsProviderChain();
            }
        }
    }
    
    /**
     * Creates ClientConfiguration from entity (following Lambda pattern exactly)
     */
    private ClientConfiguration createClientConfiguration(ConfigContext ctx, Entity entity) throws Exception {
        ClientConfiguration clientConfig = new ClientConfiguration();
        
        if (entity == null) {
            Trace.debug("using empty default ClientConfiguration");
            return clientConfig;
        }
        
        // Apply configuration settings with optimized single access (exactly like Lambda)
        setIntegerConfig(clientConfig, entity, "connectionTimeout", (config, value) -> config.setConnectionTimeout(value));
        setIntegerConfig(clientConfig, entity, "maxConnections", (config, value) -> config.setMaxConnections(value));
        setIntegerConfig(clientConfig, entity, "maxErrorRetry", (config, value) -> config.setMaxErrorRetry(value));
        setStringConfig(clientConfig, entity, "protocol", (config, value) -> {
            try {
                config.setProtocol(Protocol.valueOf(value));
            } catch (IllegalArgumentException e) {
                Trace.error("Invalid protocol value: " + value);
            }
        });
        setIntegerConfig(clientConfig, entity, "socketTimeout", (config, value) -> config.setSocketTimeout(value));
        setStringConfig(clientConfig, entity, "userAgent", (config, value) -> config.setUserAgent(value));
        setStringConfig(clientConfig, entity, "proxyHost", (config, value) -> config.setProxyHost(value));
        setIntegerConfig(clientConfig, entity, "proxyPort", (config, value) -> config.setProxyPort(value));
        setStringConfig(clientConfig, entity, "proxyUsername", (config, value) -> config.setProxyUsername(value));
        setEncryptedConfig(clientConfig, ctx, entity, "proxyPassword");
        setStringConfig(clientConfig, entity, "proxyDomain", (config, value) -> config.setProxyDomain(value));
        setStringConfig(clientConfig, entity, "proxyWorkstation", (config, value) -> config.setProxyWorkstation(value));
        
        // Handle socket buffer size hints (both must exist) - exactly like Lambda
        try {
            Integer sendHint = entity.getIntegerValue("socketSendBufferSizeHint");
            Integer receiveHint = entity.getIntegerValue("socketReceiveBufferSizeHint");
            if (sendHint != null && receiveHint != null) {
                clientConfig.setSocketBufferSizeHints(sendHint, receiveHint);
            }
        } catch (Exception e) {
            // Both fields don't exist, skip silently
        }
        
        return clientConfig;
    }
    
    /**
     * Helper methods for ClientConfiguration (exactly like Lambda)
     */
    private void setIntegerConfig(ClientConfiguration config, Entity entity, String fieldName, java.util.function.BiConsumer<ClientConfiguration, Integer> setter) {
        try {
            Integer value = entity.getIntegerValue(fieldName);
            if (value != null) {
                setter.accept(config, value);
            }
        } catch (Exception e) {
            // Field doesn't exist, skip silently
        }
    }
    
    private void setStringConfig(ClientConfiguration config, Entity entity, String fieldName, java.util.function.BiConsumer<ClientConfiguration, String> setter) {
        try {
            String value = entity.getStringValue(fieldName);
            if (value != null && !value.trim().isEmpty()) {
                setter.accept(config, value);
            }
        } catch (Exception e) {
            // Field doesn't exist, skip silently
        }
    }
    
    private void setEncryptedConfig(ClientConfiguration config, ConfigContext ctx, Entity entity, String fieldName) {
        try {
            byte[] encryptedValue = entity.getEncryptedValue(fieldName);
            if (encryptedValue != null && encryptedValue.length > 0) {
                String value = new String(encryptedValue);
                if (!value.trim().isEmpty()) {
                    config.setProxyPassword(value);
                }
            }
        } catch (Exception e) {
            // Field doesn't exist, skip silently
        }
    }
    
    /**
     * Creates AWSCredentialsProvider (following Lambda pattern)
     */
    private AWSCredentialsProvider getAWSCredentialsProvider(final AWSCredentials awsCredentials) {
        return new AWSCredentialsProvider() {
            public AWSCredentials getCredentials() {
                return awsCredentials;
            }
            public void refresh() {}
        };
    }

    // Lazy initialization getters for selectors
    private Selector<String> getUserPoolId() {
        if (userPoolId == null) {
            userPoolId = new Selector(entity.getStringValue("userPoolId"), String.class);
        }
        return userPoolId;
    }
    
    private Selector<String> getClientId() {
        if (clientId == null) {
            clientId = new Selector(entity.getStringValue("clientId"), String.class);
        }
        return clientId;
    }
    
    private Selector<String> getAwsRegion() {
        if (awsRegion == null) {
            awsRegion = new Selector(entity.getStringValue("awsRegion"), String.class);
        }
        return awsRegion;
    }
    
    private Selector<String> getCredentialType() {
        if (credentialType == null) {
            credentialType = new Selector(entity.getStringValue("credentialType"), String.class);
        }
        return credentialType;
    }
    
    private Selector<String> getAwsCredential() {
        if (awsCredential == null) {
            awsCredential = new Selector(entity.getStringValue("awsCredential"), String.class);
        }
        return awsCredential;
    }
    
    private Selector<String> getClientConfiguration() {
        if (clientConfiguration == null) {
            clientConfiguration = new Selector(entity.getStringValue("clientConfiguration"), String.class);
        }
        return clientConfiguration;
    }
    
    private Selector<String> getCredentialsFilePath() {
        if (credentialsFilePath == null) {
            credentialsFilePath = new Selector(entity.getStringValue("credentialsFilePath") != null ? entity.getStringValue("credentialsFilePath") : "", String.class);
        }
        return credentialsFilePath;
    }
    
    private Selector<String> getScopesInput() {
        if (scopesInput == null) {
            scopesInput = new Selector(entity.getStringValue("scopesInput") != null ? entity.getStringValue("scopesInput") : "", String.class);
        }
        return scopesInput;
    }

    // Métodos "safe" para uso durante filterAttached (sem contexto de Message)
    private String getCredentialTypeSafe() {
        try {
            String rawValue = entity.getStringValue("credentialType");
            if (rawValue != null && !rawValue.contains("${")) {
                // Valor literal, sem EL
                return rawValue;
            }
            // Se contém EL, usar valor padrão
            return "iam"; // Default padrão
        } catch (Exception e) {
            Trace.error("Erro ao obter credentialType: " + e.getMessage());
            return "iam"; // Default padrão
        }
    }
    
    private String getCredentialsFilePathSafe() {
        try {
            String rawValue = entity.getStringValue("credentialsFilePath");
            if (rawValue != null && !rawValue.contains("${")) {
                // Valor literal, sem EL
                return rawValue;
            }
            // Se contém EL, retornar vazio
            return "";
        } catch (Exception e) {
            Trace.error("Erro ao obter credentialsFilePath: " + e.getMessage());
            return "";
        }
    }

    private AWSCredentialsProvider createCredentialsProviderSafe() {
        try {
            return createCredentialsProvider(ctx, entity);
        } catch (Exception e) {
            Trace.info("⚠️ Não foi possível criar CredentialsProvider durante filterAttached: " + e.getMessage());
            return null; // Será criado durante invoke
        }
    }

    private ClientConfiguration createClientConfigurationSafe() {
        try {
            return createClientConfiguration(ctx, entity);
        } catch (Exception e) {
            Trace.info("⚠️ Erro ao criar ClientConfiguration, usando padrão: " + e.getMessage());
            return new ClientConfiguration(); // Configuração padrão
        }
    }

    private String getRegion(Message message) {
        try {
            Selector<String> awsRegionSelector = getAwsRegion();
            
            if (awsRegionSelector == null) {
                Trace.info("Selector awsRegion não configurado, usando região padrão: us-east-1");
                return "us-east-1";
            }
            
            // Pegar o valor raw do entity para debug
            String rawRegionValue = entity.getStringValue("awsRegion");
            Trace.info("🔍 DEBUG REGIÃO - Valor raw da entity: " + rawRegionValue);
            
            String awsRegionValue = awsRegionSelector.substitute(message);
            Trace.info("🔍 DEBUG REGIÃO - Valor após substitute: " + awsRegionValue);
            
            if (awsRegionValue != null && !awsRegionValue.trim().isEmpty()) {
                Trace.info("✅ Usando região configurada: " + awsRegionValue);
                return awsRegionValue;
            }
            
            Trace.info("⚠️ Região não configurada ou vazia, usando padrão: us-east-1");
            Trace.info("⚠️ rawRegionValue=" + rawRegionValue + ", awsRegionValue=" + awsRegionValue);
            return "us-east-1"; // Default
        } catch (Exception e) {
            Trace.error("❌ Erro ao processar região: " + e.getMessage());
            e.printStackTrace();
            return "us-east-1"; // Default
        }
    }

    /**
     * Descobre scopes do Cognito
     */
    private Map<String, String> discoverScopesFromCognito(String userPoolId, String clientId) throws Exception {
        // Validação explícita do cognitoClient
        if (cognitoClient == null) {
            throw new Exception("❌ ERRO DE INICIALIZAÇÃO: Cliente Cognito não foi inicializado. " +
                "Possíveis causas: " +
                "1) Credenciais AWS inválidas ou expiradas " +
                "2) Região AWS incorreta " +
                "3) Permissões IAM insuficientes " +
                "4) Configuração de rede (proxy/firewall) " +
                "5) Problema na configuração do filtro");
        }

        Map<String, String> scopePrefixes = new HashMap<>();

        try {
            Trace.info("Consultando Cognito - UserPool: " + userPoolId + ", Client: " + clientId);
            
            DescribeUserPoolClientRequest clientRequest = new DescribeUserPoolClientRequest()
                    .withUserPoolId(userPoolId)
                    .withClientId(clientId);

            DescribeUserPoolClientResult clientResult = cognitoClient.describeUserPoolClient(clientRequest);
            UserPoolClientType client = clientResult.getUserPoolClient();

            if (client == null) {
                throw new Exception("Client não encontrado: " + clientId);
            }

            Trace.info("Client encontrado: " + client.getClientName());

            // O Client pode ter acesso a múltiplos Resource Servers
            // Precisamos descobrir quais Resource Servers este Client específico tem acesso
            List<String> allowedScopes = client.getAllowedOAuthScopes();
            if (allowedScopes != null && !allowedScopes.isEmpty()) {
                processScopesBatch(allowedScopes, userPoolId, clientId, scopePrefixes);
            }

            Trace.info("Total de scopes descobertos para Client " + clientId + ": " + scopePrefixes.size());

        } catch (Exception e) {
            // Tratamento de erros específicos da AWS
            String errorMessage = e.getMessage();
            String errorType = e.getClass().getSimpleName();
            
            if (errorMessage != null) {
                if (errorMessage.contains("UnauthorizedOperation") || errorMessage.contains("AccessDenied")) {
                    throw new Exception("❌ ERRO DE PERMISSÃO: " + errorMessage + 
                        ". Verifique se a role/usuário AWS tem permissões para: " +
                        "cognito-idp:DescribeUserPoolClient, cognito-idp:ListResourceServers");
                        
                } else if (errorMessage.contains("InvalidUserPoolId") || errorMessage.contains("UserPoolNotFound")) {
                    throw new Exception("❌ USER POOL INVÁLIDO: " + errorMessage + 
                        ". Verifique se o User Pool ID '" + userPoolId + "' está correto e na região correta");
                        
                } else if (errorMessage.contains("InvalidClientId") || errorMessage.contains("ResourceNotFoundException")) {
                    throw new Exception("❌ CLIENT ID INVÁLIDO: " + errorMessage + 
                        ". Verifique se o Client ID '" + clientId + "' existe no User Pool '" + userPoolId + "'");
                        
                } else if (errorMessage.contains("CredentialsNotAvailable") || errorMessage.contains("Unable to load credentials")) {
                    throw new Exception("❌ ERRO DE CREDENCIAIS: " + errorMessage + 
                        ". Verifique a configuração das credenciais AWS (IAM role, arquivo de credenciais, etc.)");
                        
                } else if (errorMessage.contains("UnknownHost") || errorMessage.contains("Connection") || errorMessage.contains("timeout")) {
                    throw new Exception("❌ ERRO DE CONECTIVIDADE: " + errorMessage + 
                        ". Verifique conexão com a internet, proxy ou firewall");
                        
                } else if (errorMessage.contains("SignatureDoesNotMatch") || errorMessage.contains("InvalidSignature")) {
                    throw new Exception("❌ ERRO DE ASSINATURA: " + errorMessage + 
                        ". Verifique se as credenciais AWS estão corretas e não expiraram");
                }
            }
            
            // Erro genérico
            Trace.error("Erro ao descobrir scopes (" + errorType + "): " + errorMessage);
            throw new Exception("❌ ERRO AWS COGNITO (" + errorType + "): " + errorMessage + 
                ". Verifique logs para mais detalhes");
        }

        return scopePrefixes;
    }

    /**
     * Descobre qual Resource Server um Client específico tem acesso para um scope
     * 
     * IMPORTANTE: A AWS Cognito retorna os scopes no formato: {resource-server-identifier}/{scope-name}
     * Por exemplo: "solar-system-data/sunproximity.read" onde:
     * - "solar-system-data" é o Resource Server Identifier
     * - "sunproximity.read" é o Scope Name
     */
    private String findResourceServerForClientScope(String userPoolId, String clientId, String scope) {
        try {
            // Otimização: usar indexOf em vez de split para melhor performance
            int slashIndex = scope.indexOf('/');
            if (slashIndex > 0) {
                String resourceServerIdentifier = scope.substring(0, slashIndex);
                String scopeName = scope.substring(slashIndex + 1);
                Trace.info("Scope já está no formato completo: " + scope + 
                          " (Resource Server: " + resourceServerIdentifier + ", Scope: " + scopeName + ")");
                return resourceServerIdentifier;
            }

            // Se chegou aqui, o scope está no formato simples (apenas scope-name)
            // Precisamos descobrir qual Resource Server contém este scope
            return findResourceServerBySimpleScope(userPoolId, scope);

        } catch (Exception e) {
            Trace.error("Erro ao descobrir Resource Server para scope '" + scope + "': " + e.getMessage());
            return null;
        }
    }

    /**
     * Encontra o Resource Server que contém um scope simples (sem prefixo)
     */
    private String findResourceServerBySimpleScope(String userPoolId, String simpleScope) {
        try {
            ListResourceServersRequest serversRequest = new ListResourceServersRequest()
                    .withUserPoolId(userPoolId);

            ListResourceServersResult serversResult = cognitoClient.listResourceServers(serversRequest);
            List<ResourceServerType> resourceServers = serversResult.getResourceServers();

            if (resourceServers == null || resourceServers.isEmpty()) {
                return null;
            }

            // Procurar o scope em todos os Resource Servers
            for (ResourceServerType server : resourceServers) {
                String serverIdentifier = server.getIdentifier();
                
                if (server.getScopes() != null) {
                    for (ResourceServerScopeType serverScope : server.getScopes()) {
                        if (simpleScope.equals(serverScope.getScopeName())) {
                            return serverIdentifier;
                        }
                    }
                }
            }

            return null;

        } catch (Exception e) {
            Trace.error("Erro ao buscar Resource Server para scope '" + simpleScope + "': " + e.getMessage());
            return null;
        }
    }



    /**
     * Normaliza e separa scopes de entrada (suporta vírgulas e espaços como separadores)
     * 
     * @param scopesInput String com scopes separados por vírgulas ou espaços
     * @return Lista de scopes normalizados (sem espaços extras)
     */
    private List<String> parseScopes(String scopesInput) {
        List<String> scopes = new ArrayList<>();
        
        if (scopesInput == null || scopesInput.trim().isEmpty()) {
            return scopes;
        }
        
        // Primeiro, normalizar: substituir vírgulas por espaços e depois fazer split por espaços múltiplos
        String normalized = scopesInput.replace(',', ' ').trim();
        
        // Split por um ou mais espaços em branco
        String[] parts = normalized.split("\\s+");
        
        for (String part : parts) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                scopes.add(trimmed);
            }
        }
        
        return scopes;
    }

    /**
     * Processa scopes de entrada (suporta vírgulas e espaços como separadores)
     */
    private String processInputScopes(String scopesInput) {
        if (scopesInput == null || scopesInput.trim().isEmpty()) {
            return "";
        }
        
        List<String> scopes = parseScopes(scopesInput);
        return String.join(", ", scopes);
    }

    /**
     * Processa scopes em batch com otimizações de string
     */
    private void processScopesBatch(List<String> scopes, String userPoolId, String clientId, Map<String, String> scopePrefixes) throws Exception {
        int mappedCount = 0;
        int errorCount = 0;
        
        for (String scope : scopes) {
            // Otimização: usar indexOf em vez de split para melhor performance
            int slashIndex = scope.indexOf('/');
            if (slashIndex > 0) {   
                // Scope já está no formato completo (resource-server/scope-name)
                String resourceServerIdentifier = scope.substring(0, slashIndex);
                String scopeName = scope.substring(slashIndex + 1);
                // Mapear o scope simples para o scope completo
                scopePrefixes.put(scopeName, scope);
                mappedCount++;
            } else {
                // Scope simples, descobrir qual Resource Server contém este scope
                String prefix = findResourceServerForClientScope(userPoolId, clientId, scope);
                if (prefix != null) {
                    scopePrefixes.put(scope, prefix + "/" + scope);
                    mappedCount++;
                } else {
                    // Scope sem prefixo válido - erro ao invés de aceitar
                    errorCount++;
                    Trace.error("Scope sem Resource Server válido: " + scope);
                    throw new Exception("invalid_scope: " + scope + " (não encontrado em nenhum Resource Server)");
                }
            }
        }
        
        // Log consolidado ao final
        Trace.info("Processamento de scopes concluído - Mapeados: " + mappedCount + ", Erros: " + errorCount);
    }

    /**
     * Mapeia scopes de entrada para scopes completos (suporta vírgulas e espaços como separadores)
     */
    private String mapInputScopes(String scopesInput, Map<String, String> scopePrefixes) throws Exception {
        if (scopesInput == null || scopesInput.trim().isEmpty()) {
            return "";
        }
        
        // Usar o método auxiliar que suporta vírgulas e espaços
        List<String> scopes = parseScopes(scopesInput);
        List<String> mappedScopes = new ArrayList<>();
        
        for (String cleanScope : scopes) {
            String fullScope = scopePrefixes.get(cleanScope);
            if (fullScope != null) {
                mappedScopes.add(fullScope);
            } else {
                // Scope não encontrado - retorna erro ao invés de fallback
                Trace.error("Scope inválido não encontrado: " + cleanScope);
                throw new Exception("invalid_scope: " + cleanScope);
            }
        }
        return String.join(" ", mappedScopes); // Formato esperado pelo Cognito
    }

    /**
     * Gera um slug a partir do userPoolId
     */
    private String generateUserPoolIdSlug(String userPoolId) {
        if (userPoolId == null || userPoolId.trim().isEmpty()) {
            return "";
        }
        // Remove caracteres não alfanuméricos exceto hífens e converte para minúsculas
        return userPoolId.toLowerCase().replaceAll("[^a-z0-9-]", "");
    }
}
