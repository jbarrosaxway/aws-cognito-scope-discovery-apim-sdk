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
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientRequest;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientResult;
import com.amazonaws.services.cognitoidp.model.ListResourceServersRequest;
import com.amazonaws.services.cognitoidp.model.ListResourceServersResult;
import com.amazonaws.services.cognitoidp.model.ResourceServerType;
import com.amazonaws.services.cognitoidp.model.ResourceServerScopeType;
import com.amazonaws.services.cognitoidp.model.UserPoolClientType;

/**
 * Processador para descoberta dinâmica de scopes do AWS Cognito
 * 
 * Esta classe consulta o Cognito para descobrir automaticamente quais scopes
 * estão disponíveis para um determinado clientId, eliminando a necessidade
 * de mapeamentos fixos de scopes.
 */
public class CognitoScopeDiscoveryProcessor {

    // Configuração
    private String userPoolId;
    private String clientId;
    private String awsRegion;
    private String credentialType;
    private String awsCredential;
    private String credentialsFilePath;

    // Cliente Cognito
    private AWSCognitoIdentityProvider cognitoClient;
    
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

    /**
     * Configura o processador
     */
    public void configure(String userPoolId, String clientId, String awsRegion, 
                         String credentialType, String awsCredential, String credentialsFilePath) {
        this.userPoolId = userPoolId;
        this.clientId = clientId;
        this.awsRegion = awsRegion;
        this.credentialType = credentialType;
        this.awsCredential = awsCredential;
        this.credentialsFilePath = credentialsFilePath;
        
        initializeCognitoClient();
    }

    /**
     * Inicializa o cliente Cognito
     */
    private void initializeCognitoClient() {
        try {
            ClientConfiguration clientConfig = new ClientConfiguration();
            AWSCredentialsProvider credentialsProvider = createCredentialsProvider();
            String region = getRegion();

            this.cognitoClient = AWSCognitoIdentityProviderClientBuilder.standard()
                    .withCredentials(credentialsProvider)
                    .withRegion(region)
                    .withClientConfiguration(clientConfig)
                    .build();

            System.out.println("Cliente Cognito inicializado com sucesso");

        } catch (Exception e) {
            System.err.println("Erro ao inicializar cliente Cognito: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Cria o provider de credenciais AWS
     */
    private AWSCredentialsProvider createCredentialsProvider() throws Exception {
        if ("iam".equalsIgnoreCase(credentialType)) {
            System.out.println("Using IAM Role credentials - WebIdentityTokenCredentialsProvider");
            return new WebIdentityTokenCredentialsProvider();
        } else if ("file".equalsIgnoreCase(credentialType)) {
            if (credentialsFilePath == null || credentialsFilePath.trim().isEmpty()) {
                throw new IllegalArgumentException("credentialsFilePath é obrigatório quando credentialType é 'file'");
            }
            System.out.println("Using AWS credentials file: " + credentialsFilePath);
            return new PropertiesFileCredentialsProvider(credentialsFilePath);
        } else if ("local".equalsIgnoreCase(credentialType)) {
            System.out.println("Using local AWS credentials");
            return new DefaultAWSCredentialsProviderChain();
        } else {
            throw new IllegalArgumentException("Tipo de credencial inválido: " + credentialType);
        }
    }

    private String getRegion() {
        if (awsRegion != null && !awsRegion.trim().isEmpty()) {
            return awsRegion;
        }
        return "us-east-1"; // Default
    }

    /**
     * Executa a descoberta de scopes
     */
    public Map<String, Object> discoverScopes(String scopesInput) {
        Map<String, Object> result = new HashMap<>();
        
        try {
            if (userPoolId == null || userPoolId.trim().isEmpty()) {
                throw new IllegalArgumentException("userPoolId é obrigatório");
            }
            if (clientId == null || clientId.trim().isEmpty()) {
                throw new IllegalArgumentException("clientId é obrigatório");
            }

            String cacheKey = userPoolId + ":" + clientId;
            CacheEntry cachedEntry = scopeCache.get(cacheKey);

            if (cachedEntry != null && !cachedEntry.isExpired()) {
                System.out.println("Usando scopes do cache para " + cacheKey);
                setOutputProperties(result, cachedEntry);
                result.put("cognito.scopes.cache_hit", true);
                return result;
            }

            System.out.println("Descobrindo scopes do Cognito para userPoolId: " + userPoolId + ", clientId: " + clientId);

            Map<String, String> scopePrefixes = discoverScopesFromCognito(userPoolId, clientId);

            CacheEntry newEntry = new CacheEntry(scopePrefixes);
            scopeCache.put(cacheKey, newEntry);

            setOutputProperties(result, newEntry);
            result.put("cognito.scopes.cache_hit", false);

            if (scopesInput != null && !scopesInput.trim().isEmpty()) {
                String processedInput = processInputScopes(scopesInput);
                String mappedInput = mapInputScopes(scopesInput, scopePrefixes);

                result.put("cognito.scopes.input_processed", processedInput);
                result.put("cognito.scopes.input_mapped", mappedInput);

                System.out.println("Scopes de entrada processados: " + processedInput);
                System.out.println("Scopes de entrada mapeados: " + mappedInput);
            } else {
                result.put("cognito.scopes.input_processed", "");
                result.put("cognito.scopes.input_mapped", "");
                System.out.println("Nenhum scope de entrada fornecido");
            }

            System.out.println("Descoberta de scopes Cognito concluída com sucesso");
            result.put("success", true);

        } catch (Exception e) {
            System.err.println("Erro na descoberta de scopes Cognito: " + e.getMessage());
            e.printStackTrace();
            result.put("success", false);
            result.put("cognito.scopes.error", "ERROR");
            result.put("cognito.scopes.error_description", e.getMessage());
        }
        
        return result;
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

            System.out.println("Client encontrado: " + client.getClientName());

            ListResourceServersRequest serversRequest = new ListResourceServersRequest()
                    .withUserPoolId(userPoolId);

            ListResourceServersResult serversResult = cognitoClient.listResourceServers(serversRequest);
            List<ResourceServerType> resourceServers = serversResult.getResourceServers();

            if (client.getAllowedOAuthScopes() != null) {
                for (String scope : client.getAllowedOAuthScopes()) {
                    String prefix = findResourceServerPrefix(scope, resourceServers);
                    if (prefix != null) {
                        scopePrefixes.put(scope, prefix);
                        System.out.println("Scope mapeado: " + scope + " -> " + prefix);
                    } else {
                        scopePrefixes.put(scope, "");
                        System.out.println("Scope sem prefixo: " + scope);
                    }
                }
            }

            System.out.println("Total de scopes descobertos: " + scopePrefixes.size());

        } catch (Exception e) {
            System.err.println("Erro ao descobrir scopes: " + e.getMessage());
            throw e;
        }

        return scopePrefixes;
    }

    /**
     * Encontra o prefixo do resource server para um scope
     */
    private String findResourceServerPrefix(String scope, List<ResourceServerType> resourceServers) {
        for (ResourceServerType server : resourceServers) {
            if (server.getScopes() != null) {
                for (ResourceServerScopeType serverScope : server.getScopes()) {
                    if (scope.equals(serverScope.getScopeName())) {
                        return server.getIdentifier();
                    }
                }
            }
        }
        return null;
    }

    /**
     * Define as propriedades de saída
     */
    private void setOutputProperties(Map<String, Object> result, CacheEntry entry) {
        Map<String, String> scopePrefixes = entry.getScopePrefixes();

        List<String> availableScopes = new ArrayList<>(scopePrefixes.keySet());
        result.put("cognito.scopes.available", String.join(", ", availableScopes));

        List<String> mappedScopes = new ArrayList<>();
        for (Map.Entry<String, String> entry2 : scopePrefixes.entrySet()) {
            if (entry2.getValue() != null && !entry2.getValue().isEmpty()) {
                mappedScopes.add(entry2.getValue() + "/" + entry2.getKey());
            } else {
                mappedScopes.add(entry2.getKey());
            }
        }
        result.put("cognito.scopes.mapped", String.join(", ", mappedScopes));

        List<String> prefixes = new ArrayList<>();
        for (String prefix : scopePrefixes.values()) {
            if (prefix != null && !prefix.isEmpty() && !prefixes.contains(prefix)) {
                prefixes.add(prefix);
            }
        }
        result.put("cognito.scopes.prefixes", String.join(", ", prefixes));

        result.put("cognito.scopes.count", availableScopes.size());
        result.put("cognito.scopes.last_updated", entry.getLastUpdated().toString());
    }

    /**
     * Processa scopes de entrada
     */
    private String processInputScopes(String scopesInput) {
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
     * Mapeia scopes de entrada para scopes completos
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
                if (prefix != null && !prefix.isEmpty()) {
                    mappedScopes.add(prefix + "/" + scope.trim());
                } else {
                    mappedScopes.add(scope.trim());
                }
            }
        }
        return String.join(" ", mappedScopes); // Formato esperado pelo Cognito
    }
}
