package com.axway.aws.cognito;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Exemplo de implementação do mapeamento de scopes para AWS Cognito
 * 
 * Este exemplo mostra como resolver o problema do formato obrigatório:
 * - Cliente quer usar: "read", "write", "admin"
 * - Cognito exige: "default-m2m-resource-server-sjv0xi/read"
 */
public class CognitoScopeMappingExample {

    // Mapeamento padrão para scopes comuns
    private static final Map<String, String> DEFAULT_SCOPE_MAPPING = new HashMap<>();
    
    static {
        // Scopes padrão do Cognito
        DEFAULT_SCOPE_MAPPING.put("openid", "openid");
        DEFAULT_SCOPE_MAPPING.put("profile", "profile");
        DEFAULT_SCOPE_MAPPING.put("email", "email");
        DEFAULT_SCOPE_MAPPING.put("aws.cognito.signin.user.admin", "aws.cognito.signin.user.admin");
        
        // Scopes customizados (serão mapeados com prefixo)
        DEFAULT_SCOPE_MAPPING.put("read", "default-m2m-resource-server-sjv0xi/read");
        DEFAULT_SCOPE_MAPPING.put("write", "default-m2m-resource-server-sjv0xi/write");
        DEFAULT_SCOPE_MAPPING.put("delete", "default-m2m-resource-server-sjv0xi/delete");
        DEFAULT_SCOPE_MAPPING.put("admin", "default-m2m-resource-server-sjv0xi/admin");
        DEFAULT_SCOPE_MAPPING.put("create", "default-m2m-resource-server-sjv0xi/create");
        DEFAULT_SCOPE_MAPPING.put("update", "default-m2m-resource-server-sjv0xi/update");
    }
    
    // Configuração de prefixo customizado
    private String customScopePrefix;
    
    // Mapeamento customizado
    private Map<String, String> customScopeMapping;
    
    public CognitoScopeMappingExample() {
        this.customScopePrefix = null;
        this.customScopeMapping = new HashMap<>();
    }
    
    /**
     * Construtor com prefixo customizado
     */
    public CognitoScopeMappingExample(String customScopePrefix) {
        this.customScopePrefix = customScopePrefix;
        this.customScopeMapping = new HashMap<>();
    }
    
    /**
     * Adiciona mapeamento customizado
     */
    public void addCustomScopeMapping(String simpleScope, String fullScope) {
        this.customScopeMapping.put(simpleScope, fullScope);
    }
    
    /**
     * Define prefixo customizado para scopes
     */
    public void setCustomScopePrefix(String prefix) {
        this.customScopePrefix = prefix;
    }
    
    /**
     * Mapeia scope simples para completo
     */
    public String mapScope(String simpleScope) {
        if (simpleScope == null || simpleScope.trim().isEmpty()) {
            return simpleScope;
        }
        
        String trimmedScope = simpleScope.trim();
        
        // 1. Verificar se já tem formato completo (contém "/")
        if (isFullScope(trimmedScope)) {
            return trimmedScope;
        }
        
        // 2. Verificar mapeamento customizado
        if (customScopeMapping.containsKey(trimmedScope)) {
            return customScopeMapping.get(trimmedScope);
        }
        
        // 3. Verificar mapeamento padrão
        if (DEFAULT_SCOPE_MAPPING.containsKey(trimmedScope)) {
            return DEFAULT_SCOPE_MAPPING.get(trimmedScope);
        }
        
        // 4. Usar prefixo customizado se configurado
        if (customScopePrefix != null && !customScopePrefix.trim().isEmpty()) {
            return customScopePrefix + "/" + trimmedScope;
        }
        
        // 5. Retornar como está (pode causar erro no Cognito)
        return trimmedScope;
    }
    
    /**
     * Mapeia múltiplos scopes
     */
    public String mapScopes(String scopes) {
        if (scopes == null || scopes.trim().isEmpty()) {
            return scopes;
        }
        
        String[] scopeArray = scopes.split("\\s+");
        StringBuilder mappedScopes = new StringBuilder();
        
        for (int i = 0; i < scopeArray.length; i++) {
            if (i > 0) {
                mappedScopes.append(" ");
            }
            mappedScopes.append(mapScope(scopeArray[i]));
        }
        
        return mappedScopes.toString();
    }
    
    /**
     * Verifica se o scope já tem formato completo
     */
    private boolean isFullScope(String scope) {
        // Padrão: resource-server/scope-name
        Pattern fullScopePattern = Pattern.compile("^[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+$");
        return fullScopePattern.matcher(scope).matches();
    }
    
    /**
     * Obtém todos os scopes mapeados
     */
    public Map<String, String> getAllMappedScopes() {
        Map<String, String> allMappings = new HashMap<>();
        
        // Adicionar mapeamentos padrão
        allMappings.putAll(DEFAULT_SCOPE_MAPPING);
        
        // Adicionar mapeamentos customizados
        allMappings.putAll(customScopeMapping);
        
        return allMappings;
    }
    
    /**
     * Valida se um scope é válido
     */
    public boolean isValidScope(String scope) {
        if (scope == null || scope.trim().isEmpty()) {
            return false;
        }
        
        String mappedScope = mapScope(scope);
        
        // Se o scope foi mapeado para o mesmo valor, pode ser inválido
        if (scope.equals(mappedScope) && !isFullScope(scope)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Exemplo de uso
     */
    public static void main(String[] args) {
        System.out.println("=== Exemplo de Mapeamento de Scopes ===\n");
        
        // Exemplo 1: Mapeamento padrão
        CognitoScopeMappingExample mapper1 = new CognitoScopeMappingExample();
        
        System.out.println("1. Mapeamento Padrão:");
        System.out.println("   read -> " + mapper1.mapScope("read"));
        System.out.println("   write -> " + mapper1.mapScope("write"));
        System.out.println("   openid -> " + mapper1.mapScope("openid"));
        System.out.println("   profile -> " + mapper1.mapScope("profile"));
        System.out.println("   email -> " + mapper1.mapScope("email"));
        System.out.println();
        
        // Exemplo 2: Mapeamento com prefixo customizado
        CognitoScopeMappingExample mapper2 = new CognitoScopeMappingExample("my-api");
        
        System.out.println("2. Mapeamento com Prefixo Customizado:");
        System.out.println("   read -> " + mapper2.mapScope("read"));
        System.out.println("   write -> " + mapper2.mapScope("write"));
        System.out.println("   admin -> " + mapper2.mapScope("admin"));
        System.out.println();
        
        // Exemplo 3: Mapeamento customizado
        CognitoScopeMappingExample mapper3 = new CognitoScopeMappingExample();
        mapper3.addCustomScopeMapping("user.read", "user-management/read");
        mapper3.addCustomScopeMapping("user.write", "user-management/write");
        mapper3.addCustomScopeMapping("reports", "analytics/reports");
        
        System.out.println("3. Mapeamento Customizado:");
        System.out.println("   user.read -> " + mapper3.mapScope("user.read"));
        System.out.println("   user.write -> " + mapper3.mapScope("user.write"));
        System.out.println("   reports -> " + mapper3.mapScope("reports"));
        System.out.println();
        
        // Exemplo 4: Múltiplos scopes
        System.out.println("4. Múltiplos Scopes:");
        String multipleScopes = "read write admin openid profile";
        System.out.println("   Original: " + multipleScopes);
        System.out.println("   Mapeado: " + mapper1.mapScopes(multipleScopes));
        System.out.println();
        
        // Exemplo 5: Validação
        System.out.println("5. Validação de Scopes:");
        System.out.println("   'read' é válido? " + mapper1.isValidScope("read"));
        System.out.println("   'invalid-scope' é válido? " + mapper1.isValidScope("invalid-scope"));
        System.out.println("   'default-m2m-resource-server-sjv0xi/read' é válido? " + mapper1.isValidScope("default-m2m-resource-server-sjv0xi/read"));
        System.out.println();
        
        // Exemplo 6: Todos os mapeamentos
        System.out.println("6. Todos os Mapeamentos Disponíveis:");
        Map<String, String> allMappings = mapper1.getAllMappedScopes();
        for (Map.Entry<String, String> entry : allMappings.entrySet()) {
            System.out.println("   " + entry.getKey() + " -> " + entry.getValue());
        }
    }
}

/**
 * Implementação para uso no filtro do Axway
 */
class CognitoScopeMapper {
    
    private static final CognitoScopeMappingExample scopeMapper = new CognitoScopeMappingExample();
    
    /**
     * Mapeia scope para uso no filtro
     */
    public static String mapScopeForFilter(String scope) {
        return scopeMapper.mapScope(scope);
    }
    
    /**
     * Mapeia múltiplos scopes para uso no filtro
     */
    public static String mapScopesForFilter(String scopes) {
        return scopeMapper.mapScopes(scopes);
    }
    
    /**
     * Configura prefixo customizado
     */
    public static void setCustomPrefix(String prefix) {
        scopeMapper.setCustomScopePrefix(prefix);
    }
    
    /**
     * Adiciona mapeamento customizado
     */
    public static void addCustomMapping(String simpleScope, String fullScope) {
        scopeMapper.addCustomScopeMapping(simpleScope, fullScope);
    }
}
