import java.util.HashMap;
import java.util.Map;

/**
 * Teste simples do mapeamento de scopes para AWS Cognito
 */
public class ScopeMappingTest {

    // Mapeamento padrão para scopes comuns
    private static final Map<String, String> SCOPE_MAPPING = new HashMap<>();
    
    static {
        // Scopes padrão do Cognito
        SCOPE_MAPPING.put("openid", "openid");
        SCOPE_MAPPING.put("profile", "profile");
        SCOPE_MAPPING.put("email", "email");
        SCOPE_MAPPING.put("aws.cognito.signin.user.admin", "aws.cognito.signin.user.admin");
        
        // Scopes customizados (serão mapeados com prefixo)
        SCOPE_MAPPING.put("read", "default-m2m-resource-server-sjv0xi/read");
        SCOPE_MAPPING.put("write", "default-m2m-resource-server-sjv0xi/write");
        SCOPE_MAPPING.put("delete", "default-m2m-resource-server-sjv0xi/delete");
        SCOPE_MAPPING.put("admin", "default-m2m-resource-server-sjv0xi/admin");
        SCOPE_MAPPING.put("create", "default-m2m-resource-server-sjv0xi/create");
        SCOPE_MAPPING.put("update", "default-m2m-resource-server-sjv0xi/update");
    }
    
    /**
     * Mapeia scope simples para completo
     */
    public static String mapScope(String simpleScope) {
        if (simpleScope == null || simpleScope.trim().isEmpty()) {
            return simpleScope;
        }
        
        String trimmedScope = simpleScope.trim();
        
        // Se já tem formato completo (contém "/"), retorna como está
        if (trimmedScope.contains("/")) {
            return trimmedScope;
        }
        
        // Mapeia scope simples para completo
        return SCOPE_MAPPING.getOrDefault(trimmedScope, trimmedScope);
    }
    
    /**
     * Mapeia múltiplos scopes
     */
    public static String mapScopes(String scopes) {
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
     * Exemplo de uso
     */
    public static void main(String[] args) {
        System.out.println("=== Exemplo de Mapeamento de Scopes ===\n");
        
        System.out.println("1. Mapeamento de Scopes Simples:");
        System.out.println("   read -> " + mapScope("read"));
        System.out.println("   write -> " + mapScope("write"));
        System.out.println("   admin -> " + mapScope("admin"));
        System.out.println("   openid -> " + mapScope("openid"));
        System.out.println("   profile -> " + mapScope("profile"));
        System.out.println("   email -> " + mapScope("email"));
        System.out.println();
        
        System.out.println("2. Mapeamento de Scopes Múltiplos:");
        String multipleScopes = "read write admin openid profile";
        System.out.println("   Original: " + multipleScopes);
        System.out.println("   Mapeado: " + mapScopes(multipleScopes));
        System.out.println();
        
        System.out.println("3. Scopes Já Completos:");
        System.out.println("   'default-m2m-resource-server-sjv0xi/read' -> " + mapScope("default-m2m-resource-server-sjv0xi/read"));
        System.out.println("   'my-api/write' -> " + mapScope("my-api/write"));
        System.out.println();
        
        System.out.println("4. Todos os Mapeamentos Disponíveis:");
        for (Map.Entry<String, String> entry : SCOPE_MAPPING.entrySet()) {
            System.out.println("   " + entry.getKey() + " -> " + entry.getValue());
        }
        
        System.out.println("\n=== Resumo ===");
        System.out.println("✅ O cliente pode usar scopes simples como 'read', 'write', 'admin'");
        System.out.println("✅ O filtro mapeia automaticamente para o formato completo");
        System.out.println("✅ Scopes já completos são preservados");
        System.out.println("✅ Múltiplos scopes são suportados");
    }
}
