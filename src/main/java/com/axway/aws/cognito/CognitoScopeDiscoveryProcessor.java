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

    // Selectors for dynamic field resolution (following Lambda pattern)
    protected Selector<String> userPoolId;
    protected Selector<String> clientId;
    protected Selector<String> awsRegion;
    protected Selector<String> credentialType;
    protected Selector<String> awsCredential;
    protected Selector<String> clientConfiguration;
    protected Selector<String> credentialsFilePath;
    protected Selector<String> scopesInput;

    // Cliente Cognito
    private AWSCognitoIdentityProvider cognitoClient;
    
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
        
        // Initialize selectors for all fields (following Lambda pattern)
        this.userPoolId = new Selector(entity.getStringValue("userPoolId"), String.class);
        this.clientId = new Selector(entity.getStringValue("clientId"), String.class);
        this.awsRegion = new Selector(entity.getStringValue("awsRegion"), String.class);
        this.credentialType = new Selector(entity.getStringValue("credentialType"), String.class);
        this.awsCredential = new Selector(entity.getStringValue("awsCredential"), String.class);
        this.clientConfiguration = new Selector(entity.getStringValue("clientConfiguration"), String.class);
        this.credentialsFilePath = new Selector(entity.getStringValue("credentialsFilePath") != null ? entity.getStringValue("credentialsFilePath") : "", String.class);
        this.scopesInput = new Selector(entity.getStringValue("scopesInput") != null ? entity.getStringValue("scopesInput") : "", String.class);
        
        // Initialize Cognito client
        initializeCognitoClient();
    }

    @Override
    public boolean invoke(Circuit circuit, Message message) throws CircuitAbortException {
        try {
            // Get values from selectors
            String userPoolIdValue = userPoolId.substitute(message);
            String clientIdValue = clientId.substitute(message);
            String scopesInputValue = scopesInput.substitute(message);
            
            if (userPoolIdValue == null || userPoolIdValue.trim().isEmpty()) {
                throw new IllegalArgumentException("userPoolId é obrigatório");
            }
            
            if (clientIdValue == null || clientIdValue.trim().isEmpty()) {
                throw new IllegalArgumentException("clientId é obrigatório");
            }

            Trace.info("Iniciando descoberta de scopes do AWS Cognito");
            Trace.info("userPoolId: " + userPoolIdValue + ", clientId: " + clientIdValue);

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

            Trace.info("Descoberta de scopes concluída com sucesso");
            return true;

        } catch (Exception e) {
            Trace.error("Erro na descoberta de scopes: " + e.getMessage());
            message.put("cognito.scopes.error", "scope_discovery_failed");
            message.put("cognito.scopes.error_description", e.getMessage());
            throw new CircuitAbortException("Erro na descoberta de scopes: " + e.getMessage(), e);
        }
    }

    /**
     * Inicializa o cliente Cognito
     */
    private void initializeCognitoClient() {
        try {
            ClientConfiguration clientConfig = createClientConfiguration(ctx, entity);
            AWSCredentialsProvider credentialsProvider = createCredentialsProvider(ctx, entity);
            String region = getRegion();

            this.cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                    .withCredentials(credentialsProvider)
                    .withRegion(region)
                    .withClientConfiguration(clientConfig)
                    .build();

            Trace.info("Cliente Cognito inicializado com sucesso");

        } catch (Exception e) {
            Trace.error("Erro ao inicializar cliente Cognito: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Creates AWSCredentialsProvider (following Lambda pattern exactly)
     */
    private AWSCredentialsProvider createCredentialsProvider(ConfigContext ctx, Entity entity) throws Exception {
        String credentialTypeValue = credentialType.substitute(null);
        
        Trace.info("=== Credentials Provider Debug ===");
        Trace.info("Credential Type Value: " + credentialTypeValue);
        
        if ("iam".equals(credentialTypeValue)) {
            // Use IAM Role - WebIdentityTokenCredentialsProvider only
            Trace.info("Using IAM Role credentials - WebIdentityTokenCredentialsProvider");
            
            // Debug IRSA configuration
            Trace.info("=== IRSA Debug ===");
            Trace.info("AWS_WEB_IDENTITY_TOKEN_FILE: " + System.getenv("AWS_WEB_IDENTITY_TOKEN_FILE"));
            Trace.info("AWS_ROLE_ARN: " + System.getenv("AWS_ROLE_ARN"));
            Trace.info("AWS_REGION: " + System.getenv("AWS_REGION"));
            
            // Use WebIdentityTokenCredentialsProvider for IAM role
            Trace.info("✅ Using WebIdentityTokenCredentialsProvider for IAM role");
            return new WebIdentityTokenCredentialsProvider();
        } else if ("file".equals(credentialTypeValue)) {
            // Use credentials file
            Trace.info("Credentials Type is 'file', checking credentialsFilePath...");
            String filePath = credentialsFilePath.substitute(null);
            Trace.info("File Path: " + filePath);
            
            if (filePath != null && !filePath.trim().isEmpty()) {
                try {
                    Trace.info("Using AWS credentials file: " + filePath);
                    // Create ProfileCredentialsProvider with file path and default profile (exactly like Lambda)
                    return new PropertiesFileCredentialsProvider(filePath);
                } catch (Exception e) {
                    Trace.error("Error loading credentials file: " + e.getMessage());
                    Trace.info("Falling back to DefaultAWSCredentialsProviderChain");
                    return new DefaultAWSCredentialsProviderChain();
                }
            } else {
                Trace.info("Credentials file path not specified, using DefaultAWSCredentialsProviderChain");
                return new DefaultAWSCredentialsProviderChain();
            }
        } else {
            // Use explicit credentials via AWSFactory (following Lambda pattern exactly)
            Trace.info("Using explicit AWS credentials via AWSFactory");
            try {
                AWSCredentials awsCredentials = AWSFactory.getCredentials(ctx, entity);
                Trace.info("AWSFactory.getCredentials() successful");
                return getAWSCredentialsProvider(awsCredentials);
            } catch (Exception e) {
                Trace.error("Error getting explicit credentials: " + e.getMessage());
                Trace.info("Falling back to DefaultAWSCredentialsProviderChain");
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

    private String getRegion() {
        String awsRegionValue = awsRegion.substitute(null);
        if (awsRegionValue != null && !awsRegionValue.trim().isEmpty()) {
            return awsRegionValue;
        }
        return "us-east-1"; // Default
    }

    /**
     * Descobre scopes do Cognito
     */
    private Map<String, String> discoverScopesFromCognito(String userPoolId, String clientId) throws Exception {
        Map<String, String> scopePrefixes = new HashMap<>();

        try {
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
            if (client.getAllowedOAuthScopes() != null) {
                for (String scope : client.getAllowedOAuthScopes()) {
                    // Para cada scope, descobrir qual Resource Server o Client tem acesso
                    String prefix = findResourceServerForClientScope(userPoolId, clientId, scope);
                    if (prefix != null) {
                        scopePrefixes.put(scope, prefix + "/" + scope);
                        Trace.info("Scope mapeado para Client " + clientId + ": " + scope + " -> " + prefix + "/" + scope);
                    } else {
                        scopePrefixes.put(scope, scope);
                        Trace.info("Scope sem prefixo para Client " + clientId + ": " + scope);
                    }
                }
            }

            Trace.info("Total de scopes descobertos para Client " + clientId + ": " + scopePrefixes.size());

        } catch (Exception e) {
            Trace.error("Erro ao descobrir scopes: " + e.getMessage());
            throw e;
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
            // Se o scope já contém o formato completo (resource-server/scope-name)
            if (scope.contains("/")) {
                String[] parts = scope.split("/", 2);
                if (parts.length == 2) {
                    String resourceServerIdentifier = parts[0];
                    String scopeName = parts[1];
                    Trace.info("Scope já está no formato completo: " + scope + 
                              " (Resource Server: " + resourceServerIdentifier + ", Scope: " + scopeName + ")");
                    return resourceServerIdentifier;
                }
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
                Trace.info("Nenhum Resource Server encontrado no User Pool: " + userPoolId);
                return null;
            }

            Trace.info("Procurando scope simples '" + simpleScope + "' em " + resourceServers.size() + " Resource Servers");

            // Procurar o scope em todos os Resource Servers
            for (ResourceServerType server : resourceServers) {
                String serverIdentifier = server.getIdentifier();
                
                if (server.getScopes() != null) {
                    for (ResourceServerScopeType serverScope : server.getScopes()) {
                        if (simpleScope.equals(serverScope.getScopeName())) {
                            Trace.info("Scope '" + simpleScope + "' encontrado no Resource Server: " + serverIdentifier);
                            return serverIdentifier;
                        }
                    }
                }
            }

            Trace.info("Scope simples '" + simpleScope + "' não encontrado em nenhum Resource Server");
            return null;

        } catch (Exception e) {
            Trace.error("Erro ao buscar Resource Server para scope simples '" + simpleScope + "': " + e.getMessage());
            return null;
        }
    }



    /**
     * Processa scopes de entrada
     */
    private String processInputScopes(String scopesInput) {
        if (scopesInput == null || scopesInput.trim().isEmpty()) {
            return "";
        }
        // Split by comma and clean up
        String[] scopes = scopesInput.split(",");
        for (int i = 0; i < scopes.length; i++) {
            scopes[i] = scopes[i].trim();
        }
        return String.join(", ", scopes);
    }

    /**
     * Mapeia scopes de entrada para scopes completos
     */
    private String mapInputScopes(String scopesInput, Map<String, String> scopePrefixes) {
        if (scopesInput == null || scopesInput.trim().isEmpty()) {
            return "";
        }
        // Split by comma, clean up, and map to full scopes
        String[] scopes = scopesInput.split(",");
        List<String> mappedScopes = new ArrayList<>();
        
        for (String scope : scopes) {
            String cleanScope = scope.trim();
            if (!cleanScope.isEmpty()) {
                String fullScope = scopePrefixes.get(cleanScope);
                if (fullScope != null) {
                    mappedScopes.add(fullScope);
                } else {
                    // Fallback: add default prefix
                    mappedScopes.add("my-api/" + cleanScope);
                }
            }
        }
        return String.join(" ", mappedScopes); // Formato esperado pelo Cognito
    }
}
