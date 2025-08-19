package com.axway.aws.cognito;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientRequest;
import com.amazonaws.services.cognitoidp.model.DescribeUserPoolClientResult;
import com.amazonaws.services.cognitoidp.model.ListResourceServersRequest;
import com.amazonaws.services.cognitoidp.model.ListResourceServersResult;
import com.amazonaws.services.cognitoidp.model.ResourceServerScopeType;
import com.amazonaws.services.cognitoidp.model.ResourceServerType;
import com.amazonaws.services.cognitoidp.model.UserPoolClientType;
import com.vordel.trace.Trace;

/**
 * Implementação da descoberta dinâmica de scopes para AWS Cognito
 * 
 * Esta classe descobre automaticamente quais scopes estão disponíveis
 * para cada clientId, eliminando a necessidade de mapeamentos fixos.
 */
public class CognitoDynamicScopeDiscovery {

    private final AWSCognitoIdentityProvider cognitoClient;
    private final CognitoScopeCache scopeCache;
    
    public CognitoDynamicScopeDiscovery(AWSCognitoIdentityProvider cognitoClient) {
        this.cognitoClient = cognitoClient;
        this.scopeCache = new CognitoScopeCache();
    }
    
    /**
     * Mapeia scope simples para completo baseado no clientId
     */
    public String mapScopeDynamically(String simpleScope, String userPoolId, String clientId) {
        if (simpleScope == null || simpleScope.trim().isEmpty()) {
            return simpleScope;
        }
        
        String trimmedScope = simpleScope.trim();
        
        // Se já tem formato completo (contém "/"), retorna como está
        if (trimmedScope.contains("/")) {
            return trimmedScope;
        }
        
        try {
            // Descobrir scopes disponíveis para este clientId
            ScopeInfo scopeInfo = scopeCache.getScopeInfo(userPoolId, clientId, cognitoClient);
            
            // Verificar se o scope simples está disponível
            String prefix = scopeInfo.getScopePrefixes().get(trimmedScope);
            if (prefix != null) {
                String fullScope = prefix + "/" + trimmedScope;
                Trace.info("Scope mapeado: '" + trimmedScope + "' -> '" + fullScope + "' para clientId: " + clientId);
                return fullScope;
            }
            
            // Se não encontrou, retorna como está (pode causar erro no Cognito)
            Trace.warning("Scope '" + trimmedScope + "' não encontrado para clientId: " + clientId);
            Trace.info("Scopes disponíveis: " + scopeInfo.getAvailableScopes());
            return trimmedScope;
            
        } catch (Exception e) {
            Trace.error("Erro ao mapear scope dinamicamente: " + e.getMessage(), e);
            return trimmedScope; // Fallback
        }
    }
    
    /**
     * Mapeia múltiplos scopes dinamicamente
     */
    public String mapScopesDynamically(String scopes, String userPoolId, String clientId) {
        if (scopes == null || scopes.trim().isEmpty()) {
            return scopes;
        }
        
        String[] scopeArray = scopes.split("\\s+");
        StringBuilder mappedScopes = new StringBuilder();
        
        for (int i = 0; i < scopeArray.length; i++) {
            if (i > 0) {
                mappedScopes.append(" ");
            }
            String mappedScope = mapScopeDynamically(scopeArray[i], userPoolId, clientId);
            mappedScopes.append(mappedScope);
        }
        
        return mappedScopes.toString();
    }
    
    /**
     * Descobre todos os scopes disponíveis para um clientId
     */
    public List<String> discoverAvailableScopes(String userPoolId, String clientId) {
        try {
            Trace.info("Descobrindo scopes para clientId: " + clientId + " no User Pool: " + userPoolId);
            
            // 1. Obter informações do app client
            DescribeUserPoolClientRequest describeRequest = new DescribeUserPoolClientRequest()
                .withUserPoolId(userPoolId)
                .withClientId(clientId);
            
            DescribeUserPoolClientResult describeResult = cognitoClient.describeUserPoolClient(describeRequest);
            UserPoolClientType client = describeResult.getUserPoolClient();
            
            // 2. Extrair scopes permitidos
            List<String> allowedScopes = new ArrayList<>();
            
            // Scopes padrão do Cognito
            if (client.getReadAttributes() != null) {
                allowedScopes.addAll(client.getReadAttributes());
                Trace.info("Scopes de leitura: " + client.getReadAttributes());
            }
            if (client.getWriteAttributes() != null) {
                allowedScopes.addAll(client.getWriteAttributes());
                Trace.info("Scopes de escrita: " + client.getWriteAttributes());
            }
            
            // Scopes customizados dos resource servers
            if (client.getAllowedOAuthScopes() != null) {
                allowedScopes.addAll(client.getAllowedOAuthScopes());
                Trace.info("Scopes OAuth permitidos: " + client.getAllowedOAuthScopes());
            }
            
            Trace.info("Total de scopes disponíveis: " + allowedScopes.size());
            return allowedScopes;
            
        } catch (Exception e) {
            Trace.error("Erro ao descobrir scopes para clientId: " + clientId, e);
            throw new RuntimeException("Erro ao descobrir scopes para clientId: " + clientId, e);
        }
    }
    
    /**
     * Descobre o prefixo do resource server para um scope
     */
    public String discoverScopePrefix(String userPoolId, String scope) {
        try {
            Trace.info("Descobrindo prefixo para scope: " + scope);
            
            // 1. Listar resource servers
            ListResourceServersRequest listRequest = new ListResourceServersRequest()
                .withUserPoolId(userPoolId);
            
            ListResourceServersResult listResult = cognitoClient.listResourceServers(listRequest);
            
            // 2. Procurar pelo scope nos resource servers
            for (ResourceServerType resourceServer : listResult.getResourceServers()) {
                String identifier = resourceServer.getIdentifier();
                Trace.info("Verificando resource server: " + identifier);
                
                if (resourceServer.getScopes() != null) {
                    for (ResourceServerScopeType scopeType : resourceServer.getScopes()) {
                        String fullScope = identifier + "/" + scopeType.getScopeName();
                        Trace.info("Scope do resource server: " + fullScope);
                        
                        if (fullScope.equals(scope)) {
                            Trace.info("Prefixo encontrado: " + identifier + " para scope: " + scope);
                            return identifier;
                        }
                    }
                }
            }
            
            Trace.warning("Prefixo não encontrado para scope: " + scope);
            return null; // Scope não encontrado
            
        } catch (Exception e) {
            Trace.error("Erro ao descobrir prefixo para scope: " + scope, e);
            throw new RuntimeException("Erro ao descobrir prefixo para scope: " + scope, e);
        }
    }
    
    /**
     * Limpa o cache para um client específico
     */
    public void invalidateCache(String userPoolId, String clientId) {
        scopeCache.invalidateCache(userPoolId, clientId);
        Trace.info("Cache invalidado para userPoolId: " + userPoolId + ", clientId: " + clientId);
    }
    
    /**
     * Limpa todo o cache
     */
    public void clearCache() {
        scopeCache.clearCache();
        Trace.info("Cache limpo completamente");
    }
    
    /**
     * Informações sobre scopes de um client
     */
    public static class ScopeInfo {
        private final List<String> availableScopes;
        private final Map<String, String> scopePrefixes;
        private final Instant lastUpdated;
        
        public ScopeInfo(List<String> availableScopes, Map<String, String> scopePrefixes, Instant lastUpdated) {
            this.availableScopes = availableScopes;
            this.scopePrefixes = scopePrefixes;
            this.lastUpdated = lastUpdated;
        }
        
        public List<String> getAvailableScopes() {
            return availableScopes;
        }
        
        public Map<String, String> getScopePrefixes() {
            return scopePrefixes;
        }
        
        public Instant getLastUpdated() {
            return lastUpdated;
        }
        
        public boolean isExpired() {
            return Instant.now().isAfter(lastUpdated.plus(Duration.ofMinutes(30)));
        }
    }
    
    /**
     * Cache inteligente de scopes com expiração
     */
    private static class CognitoScopeCache {
        
        private final Map<String, ScopeInfo> scopeCache = new ConcurrentHashMap<>();
        private final Duration cacheExpiration = Duration.ofMinutes(30);
        
        /**
         * Obtém scopes do cache ou descobre dinamicamente
         */
        public ScopeInfo getScopeInfo(String userPoolId, String clientId, AWSCognitoIdentityProvider cognitoClient) {
            String cacheKey = userPoolId + ":" + clientId;
            
            ScopeInfo cachedInfo = scopeCache.get(cacheKey);
            
            if (cachedInfo == null || cachedInfo.isExpired()) {
                Trace.info("Cache expirado ou não encontrado para: " + cacheKey + ". Descobrindo scopes...");
                
                // Descobrir dinamicamente
                CognitoDynamicScopeDiscovery discovery = new CognitoDynamicScopeDiscovery(cognitoClient);
                List<String> availableScopes = discovery.discoverAvailableScopes(userPoolId, clientId);
                
                // Mapear scopes para prefixos
                Map<String, String> scopePrefixes = new HashMap<>();
                for (String scope : availableScopes) {
                    if (scope.contains("/")) {
                        String[] parts = scope.split("/", 2);
                        scopePrefixes.put(parts[1], parts[0]); // scopeName -> prefix
                        Trace.info("Mapeamento descoberto: '" + parts[1] + "' -> '" + parts[0] + "'");
                    }
                }
                
                cachedInfo = new ScopeInfo(availableScopes, scopePrefixes, Instant.now());
                scopeCache.put(cacheKey, cachedInfo);
                
                Trace.info("Cache atualizado para: " + cacheKey + " com " + scopePrefixes.size() + " mapeamentos");
            } else {
                Trace.info("Usando cache para: " + cacheKey + " (expira em " + 
                    Duration.between(Instant.now(), cachedInfo.getLastUpdated().plus(cacheExpiration)).toMinutes() + " min)");
            }
            
            return cachedInfo;
        }
        
        /**
         * Limpa cache para um client específico
         */
        public void invalidateCache(String userPoolId, String clientId) {
            String cacheKey = userPoolId + ":" + clientId;
            scopeCache.remove(cacheKey);
        }
        
        /**
         * Limpa todo o cache
         */
        public void clearCache() {
            scopeCache.clear();
        }
    }
    
    /**
     * Exemplo de uso
     */
    public static void main(String[] args) {
        System.out.println("=== Exemplo de Descoberta Dinâmica de Scopes ===\n");
        
        // Este é apenas um exemplo - em produção, o filtro usaria as credenciais configuradas
        System.out.println("Para usar no filtro:");
        System.out.println("1. Configure as credenciais AWS no filtro");
        System.out.println("2. Configure o userPoolId");
        System.out.println("3. Use mapScopeDynamically() para mapear scopes");
        System.out.println("4. O cache será gerenciado automaticamente");
        
        System.out.println("\nExemplo de configuração:");
        System.out.println("userPoolId: us-east-1_ABCD1234");
        System.out.println("clientId: client-a-123");
        System.out.println("scope: read");
        System.out.println("Resultado: read -> my-api-a/read (descoberto automaticamente)");
    }
}
