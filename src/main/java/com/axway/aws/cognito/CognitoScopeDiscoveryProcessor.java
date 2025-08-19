package com.axway.aws.cognito;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.DefaultAWSCredentialsProviderChain;
import com.amazonaws.auth.PropertiesFileCredentialsProvider;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientRequest;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientResult;
import com.amazonaws.services.cognitoidp.model.ListResourceServersRequest;
import com.amazonaws.services.cognitoidp.model.ListResourceServersResult;
import com.amazonaws.services.cognitoidp.model.ResourceServerDescription;
import com.amazonaws.services.cognitoidp.model.UserPoolClientDescription;
import com.vordel.circuit.CircuitAbortException;
import com.vordel.circuit.Message;
import com.vordel.circuit.MessageProcessor;
import com.vordel.config.ConfigContext;
import com.vordel.es.Entity;
import com.vordel.es.EntityStoreException;
import com.vordel.trace.Trace;
import com.vordel.util.Selector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Processador para descoberta dinâmica de scopes do AWS Cognito
 * 
 * Este processador consulta o Cognito para descobrir automaticamente quais scopes
 * estão disponíveis para um determinado clientId, eliminando a necessidade
 * de mapeamentos fixos de scopes.
 */
public class CognitoScopeDiscoveryProcessor implements MessageProcessor {

    // Selectors para configuração
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
    
    // Cache para scopes descobertos (userPoolId + clientId -> CacheEntry)
    private static final Map<String, CacheEntry> scopeCache = new ConcurrentHashMap<>();
    private static final long CACHE_EXPIRATION_MS = 30 * 60 * 1000; // 30 minutos

    @Override
    public void filterAttached(ConfigContext ctx, Entity entity) throws EntityStoreException {
        // Inicializar selectors
        this.userPoolId = new Selector(entity.getStringValue("userPoolId"), String.class);
        this.clientId = new Selector(entity.getStringValue("clientId"), String.class);
        this.awsRegion = new Selector(entity.getStringValue("awsRegion"), String.class);
        this.credentialType = new Selector(entity.getStringValue("credentialType"), String.class);
        this.awsCredential = new Selector(entity.getStringValue("awsCredential"), String.class);
        this.clientConfiguration = new Selector(entity.getStringValue("clientConfiguration"), String.class);
        this.credentialsFilePath = new Selector(entity.getStringValue("credentialsFilePath"), String.class);
        this.scopesInput = new Selector(entity.getStringValue("scopesInput"), String.class);

        // Obter configuração do cliente (seguindo padrão Lambda exatamente)
        Entity clientConfig = ctx.getEntity(entity.getReferenceValue("clientConfiguration"));
        
        // Inicializar cliente Cognito
        initializeCognitoClient(ctx, entity, clientConfig);
    }

    @Override
    public boolean invoke(com.vordel.circuit.Circuit circuit, Message message) throws CircuitAbortException {
        try {
            Trace.info("Iniciando descoberta de scopes Cognito");
            
            // Obter valores dos selectors
            String userPoolIdValue = userPoolId.substitute(message);
            String clientIdValue = clientId.substitute(message);
            String scopesInputValue = scopesInput.substitute(message);
            
            if (userPoolIdValue == null || userPoolIdValue.trim().isEmpty()) {
                throw new IllegalArgumentException("userPoolId é obrigatório");
            }
            
            if (clientIdValue == null || clientIdValue.trim().isEmpty()) {
                throw new IllegalArgumentException("clientId é obrigatório");
            }

            // Verificar cache primeiro
            String cacheKey = userPoolIdValue + ":" + clientIdValue;
            CacheEntry cachedEntry = scopeCache.get(cacheKey);
            
            if (cachedEntry != null && !cachedEntry.isExpired()) {
                Trace.info("Usando scopes do cache para " + cacheKey);
                setOutputProperties(message, cachedEntry);
                message.put("cognito.scopes.cache_hit", true);
                return true;
            }

            // Descobrir scopes do Cognito
            Trace.info("Descobrindo scopes do Cognito para userPoolId: " + userPoolIdValue + ", clientId: " + clientIdValue);
            
            Map<String, String> scopePrefixes = discoverScopes(userPoolIdValue, clientIdValue);
            
            // Criar entrada do cache
            CacheEntry newEntry = new CacheEntry(scopePrefixes);
            scopeCache.put(cacheKey, newEntry);
            
            // Definir propriedades de saída
            setOutputProperties(message, newEntry);
            message.put("cognito.scopes.cache_hit", false);
            
            // Processar scopes de entrada se fornecidos
            if (scopesInputValue != null && !scopesInputValue.trim().isEmpty()) {
                String processedInput = processInputScopes(scopesInputValue, scopePrefixes);
                String mappedInput = mapInputScopes(scopesInputValue, scopePrefixes);
                
                message.put("cognito.scopes.input_processed", processedInput);
                message.put("cognito.scopes.input_mapped", mappedInput);
                
                Trace.info("Scopes de entrada processados: " + processedInput);
                Trace.info("Scopes de entrada mapeados: " + mappedInput);
            } else {
                message.put("cognito.scopes.input_processed", "");
                message.put("cognito.scopes.input_mapped", "");
                Trace.info("Nenhum scope de entrada fornecido");
            }
            
            Trace.info("Descoberta de scopes Cognito concluída com sucesso");
            return true;
            
        } catch (Exception e) {
            Trace.error("Erro na descoberta de scopes Cognito: " + e.getMessage(), e);
            message.put("cognito.scopes.error", "ERROR");
            message.put("cognito.scopes.error_description", e.getMessage());
            return false;
        }
    }

    /**
     * Inicializa o cliente Cognito com as credenciais e configuração apropriadas
     */
    private void initializeCognitoClient(ConfigContext ctx, Entity entity, Entity clientConfigEntity) throws EntityStoreException {
        try {
            // Criar configuração do cliente
            com.amazonaws.ClientConfiguration clientConfig = createClientConfiguration(clientConfigEntity);
            
            // Criar provider de credenciais
            AWSCredentialsProvider credentialsProvider = createCredentialsProvider(entity);
            
            // Criar cliente Cognito
            this.cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                    .withCredentials(credentialsProvider)
                    .withClientConfiguration(clientConfig)
                    .withRegion(awsRegion.getDefaultValue())
                    .build();
            
            Trace.info("Cliente Cognito inicializado com sucesso");
            
        } catch (Exception e) {
            Trace.error("Erro ao inicializar cliente Cognito: " + e.getMessage(), e);
            throw new EntityStoreException("Falha ao inicializar cliente Cognito", e);
        }
    }

    /**
     * Cria configuração do cliente AWS baseada na entidade referenciada
     */
    private com.amazonaws.ClientConfiguration createClientConfiguration(Entity clientConfigEntity) {
        com.amazonaws.ClientConfiguration config = new com.amazonaws.ClientConfiguration();
        
        if (clientConfigEntity != null) {
            // Ler propriedades da entidade AWSClientConfiguration
            String connectionTimeout = clientConfigEntity.getStringValue("connectionTimeout");
            String socketTimeout = clientConfigEntity.getStringValue("socketTimeout");
            String maxErrorRetry = clientConfigEntity.getStringValue("maxErrorRetry");
            String maxConnections = clientConfigEntity.getStringValue("maxConnections");
            String protocol = clientConfigEntity.getStringValue("protocol");
            String userAgent = clientConfigEntity.getStringValue("userAgent");
            String proxyHost = clientConfigEntity.getStringValue("proxyHost");
            String proxyPort = clientConfigEntity.getStringValue("proxyPort");
            String proxyUsername = clientConfigEntity.getStringValue("proxyUsername");
            String proxyPassword = clientConfigEntity.getStringValue("proxyPassword");
            String proxyDomain = clientConfigEntity.getStringValue("proxyDomain");
            String proxyWorkstation = clientConfigEntity.getStringValue("proxyWorkstation");
            String socketSendBufferSizeHint = clientConfigEntity.getStringValue("socketSendBufferSizeHint");
            String socketReceiveBufferSizeHint = clientConfigEntity.getStringValue("socketReceiveBufferSizeHint");
            
            // Aplicar configurações se fornecidas
            if (connectionTimeout != null && !connectionTimeout.trim().isEmpty()) {
                config.setConnectionTimeout(Integer.parseInt(connectionTimeout.trim()));
            }
            if (socketTimeout != null && !socketTimeout.trim().isEmpty()) {
                config.setSocketTimeout(Integer.parseInt(socketTimeout.trim()));
            }
            if (maxErrorRetry != null && !maxErrorRetry.trim().isEmpty()) {
                config.setMaxErrorRetry(Integer.parseInt(maxErrorRetry.trim()));
            }
            if (maxConnections != null && !maxConnections.trim().isEmpty()) {
                config.setMaxConnections(Integer.parseInt(maxConnections.trim()));
            }
            if (protocol != null && !protocol.trim().isEmpty()) {
                config.setProtocol(com.amazonaws.Protocol.valueOf(protocol.trim().toUpperCase()));
            }
            if (userAgent != null && !userAgent.trim().isEmpty()) {
                config.setUserAgent(userAgent.trim());
            }
            if (proxyHost != null && !proxyHost.trim().isEmpty()) {
                config.setProxyHost(proxyHost.trim());
            }
            if (proxyPort != null && !proxyPort.trim().isEmpty()) {
                config.setProxyPort(Integer.parseInt(proxyPort.trim()));
            }
            if (proxyUsername != null && !proxyUsername.trim().isEmpty()) {
                config.setProxyUsername(proxyUsername.trim());
            }
            if (proxyPassword != null && !proxyPassword.trim().isEmpty()) {
                config.setProxyPassword(proxyPassword.trim());
            }
            if (proxyDomain != null && !proxyDomain.trim().isEmpty()) {
                config.setProxyDomain(proxyDomain.trim());
            }
            if (proxyWorkstation != null && !proxyWorkstation.trim().isEmpty()) {
                config.setProxyWorkstation(proxyWorkstation.trim());
            }
            if (socketSendBufferSizeHint != null && !socketSendBufferSizeHint.trim().isEmpty()) {
                config.setSocketSendBufferSizeHint(Integer.parseInt(socketSendBufferSizeHint.trim()));
            }
            if (socketReceiveBufferSizeHint != null && !socketReceiveBufferSizeHint.trim().isEmpty()) {
                config.setSocketReceiveBufferSizeHint(Integer.parseInt(socketReceiveBufferSizeHint.trim()));
            }
        }
        
        return config;
    }

    /**
     * Cria o provider de credenciais AWS baseado na configuração
     */
    private AWSCredentialsProvider createCredentialsProvider(Entity entity) throws EntityStoreException {
        String credentialTypeValue = credentialType.getDefaultValue();
        
        if ("iam".equalsIgnoreCase(credentialTypeValue)) {
            Trace.info("Usando credenciais IAM Role");
            return new DefaultAWSCredentialsProviderChain();
        } else if ("file".equalsIgnoreCase(credentialTypeValue)) {
            String filePath = credentialsFilePath.getDefaultValue();
            if (filePath == null || filePath.trim().isEmpty()) {
                throw new EntityStoreException("credentialsFilePath é obrigatório quando credentialType é 'file'");
            }
            Trace.info("Usando credenciais do arquivo: " + filePath);
            return new PropertiesFileCredentialsProvider(filePath);
        } else if ("local".equalsIgnoreCase(credentialTypeValue)) {
            // Para credenciais locais, usar o perfil referenciado
            String profileName = awsCredential.getDefaultValue();
            if (profileName == null || profileName.trim().isEmpty()) {
                throw new EntityStoreException("awsCredential é obrigatório quando credentialType é 'local'");
            }
            Trace.info("Usando credenciais locais do perfil: " + profileName);
            return new DefaultAWSCredentialsProviderChain();
        } else {
            throw new EntityStoreException("Tipo de credencial inválido: " + credentialTypeValue);
        }
    }

    /**
     * Descobre scopes disponíveis para o clientId no userPool
     */
    private Map<String, String> discoverScopes(String userPoolId, String clientId) throws Exception {
        Map<String, String> scopePrefixes = new HashMap<>();
        
        try {
            // 1. Obter informações do client
            DescribeUserPoolClientRequest clientRequest = new DescribeUserPoolClientRequest()
                    .withUserPoolId(userPoolId)
                    .withClientId(clientId);
            
            DescribeUserPoolClientResult clientResult = cognitoClient.describeUserPoolClient(clientRequest);
            UserPoolClientDescription client = clientResult.getUserPoolClient();
            
            if (client == null) {
                throw new Exception("Client não encontrado: " + clientId);
            }
            
            Trace.info("Client encontrado: " + client.getClientName());
            
            // 2. Listar resource servers para obter prefixos
            ListResourceServersRequest serversRequest = new ListResourceServersRequest()
                    .withUserPoolId(userPoolId);
            
            ListResourceServersResult serversResult = cognitoClient.listResourceServers(serversRequest);
            List<ResourceServerDescription> resourceServers = serversResult.getResourceServers();
            
            // 3. Mapear scopes disponíveis
            if (client.getAllowedOAuthScopes() != null) {
                for (String scope : client.getAllowedOAuthScopes()) {
                    // Para cada scope, encontrar o resource server correspondente
                    String prefix = findResourceServerPrefix(scope, resourceServers);
                    if (prefix != null) {
                        scopePrefixes.put(scope, prefix);
                        Trace.info("Scope mapeado: " + scope + " -> " + prefix);
                    } else {
                        // Se não encontrar prefixo, usar scope como está
                        scopePrefixes.put(scope, "");
                        Trace.info("Scope sem prefixo: " + scope);
                    }
                }
            }
            
            Trace.info("Total de scopes descobertos: " + scopePrefixes.size());
            
        } catch (Exception e) {
            Trace.error("Erro ao descobrir scopes: " + e.getMessage(), e);
            throw e;
        }
        
        return scopePrefixes;
    }

    /**
     * Encontra o prefixo do resource server para um scope específico
     */
    private String findResourceServerPrefix(String scope, List<ResourceServerDescription> resourceServers) {
        for (ResourceServerDescription server : resourceServers) {
            if (server.getScopes() != null) {
                for (com.amazonaws.services.cognitoidp.model.ResourceServerScopeType serverScope : server.getScopes()) {
                    if (scope.equals(serverScope.getScopeName())) {
                        return server.getIdentifier();
                    }
                }
            }
        }
        return null;
    }

    /**
     * Define as propriedades de saída na mensagem
     */
    private void setOutputProperties(Message message, CacheEntry entry) {
        Map<String, String> scopePrefixes = entry.getScopePrefixes();
        
        // Lista de scopes disponíveis
        List<String> availableScopes = new ArrayList<>(scopePrefixes.keySet());
        message.put("cognito.scopes.available", String.join(", ", availableScopes));
        
        // Mapeamento de scopes
        List<String> mappedScopes = new ArrayList<>();
        for (Map.Entry<String, String> entry2 : scopePrefixes.entrySet()) {
            if (entry2.getValue() != null && !entry2.getValue().isEmpty()) {
                mappedScopes.add(entry2.getValue() + "/" + entry2.getKey());
            } else {
                mappedScopes.add(entry2.getKey());
            }
        }
        message.put("cognito.scopes.mapped", String.join(", ", mappedScopes));
        
        // Lista de prefixos
        List<String> prefixes = new ArrayList<>();
        for (String prefix : scopePrefixes.values()) {
            if (prefix != null && !prefix.isEmpty() && !prefixes.contains(prefix)) {
                prefixes.add(prefix);
            }
        }
        message.put("cognito.scopes.prefixes", String.join(", ", prefixes));
        
        // Contagem de scopes
        message.put("cognito.scopes.count", availableScopes.size());
        
        // Timestamp da última atualização
        message.put("cognito.scopes.last_updated", entry.getLastUpdated().toString());
    }

    /**
     * Processa scopes de entrada (formato URL encoded) e retorna lista limpa
     */
    private String processInputScopes(String scopesInput, Map<String, String> scopePrefixes) {
        if (scopesInput == null || scopesInput.trim().isEmpty()) {
            return "";
        }
        String[] scopes = scopesInput.trim().split(",");
        List<String> processedScopes = new ArrayList<>();
        for (String scope : scopes) {
            if (!scope.trim().isEmpty()) {
                processedScopes.add(scope.trim());
            }
        }
        return String.join(", ", processedScopes);
    }
    
    /**
     * Mapeia scopes de entrada para scopes completos com prefixos
     */
    private String mapInputScopes(String scopesInput, Map<String, String> scopePrefixes) {
        if (scopesInput == null || scopesInput.trim().isEmpty()) {
            return "";
        }
        String[] scopes = scopesInput.trim().split(",");
        List<String> mappedScopes = new ArrayList<>();
        for (String scope : scopes) {
            if (!scope.trim().isEmpty()) {
                String prefix = scopePrefixes.get(scope.trim());
                if (prefix != null) {
                    mappedScopes.add(prefix + "/" + scope.trim());
                } else {
                    mappedScopes.add(scope.trim());
                }
            }
        }
        return String.join(" ", mappedScopes); // Formato esperado pelo Cognito
    }

    /**
     * Classe interna para cache de scopes
     */
    private static class CacheEntry {
        private final Map<String, String> scopePrefixes;
        private final long timestamp;
        
        public CacheEntry(Map<String, String> scopePrefixes) {
            this.scopePrefixes = scopePrefixes;
            this.timestamp = System.currentTimeMillis();
        }
        
        public Map<String, String> getScopePrefixes() {
            return scopePrefixes;
        }
        
        public long getTimestamp() {
            return timestamp;
        }
        
        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_EXPIRATION_MS;
        }
        
        public java.time.Instant getLastUpdated() {
            return java.time.Instant.ofEpochMilli(timestamp);
        }
    }
}
