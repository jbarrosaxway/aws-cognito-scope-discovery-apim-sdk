package com.axway.aws.cognito;

import java.util.Map;

/**
 * Classe de teste para o CognitoScopeDiscoveryProcessor
 */
public class CognitoScopeDiscoveryTest {

    public static void main(String[] args) {
        System.out.println("=== Teste do CognitoScopeDiscoveryProcessor ===");
        
        // Criar instância do processador
        CognitoScopeDiscoveryProcessor processor = new CognitoScopeDiscoveryProcessor();
        
        // Configurar (valores de exemplo - substituir por valores reais)
        processor.configure(
            "us-east-1_XXXXXXXXX",  // userPoolId
            "1a2b3c4d5e6f7g8h9i0j", // clientId
            "us-east-1",            // awsRegion
            "local",                // credentialType
            "default",              // awsCredential
            null                    // credentialsFilePath
        );
        
        // Testar com scopes de entrada
        String scopesInput = "read,write,admin";
        System.out.println("Scopes de entrada: " + scopesInput);
        
        try {
            Map<String, Object> result = processor.discoverScopes(scopesInput);
            
            System.out.println("\n=== Resultado ===");
            System.out.println("Sucesso: " + result.get("success"));
            
            if (result.containsKey("cognito.scopes.error")) {
                System.out.println("Erro: " + result.get("cognito.scopes.error_description"));
            } else {
                System.out.println("Scopes disponíveis: " + result.get("cognito.scopes.available"));
                System.out.println("Scopes mapeados: " + result.get("cognito.scopes.mapped"));
                System.out.println("Prefixos: " + result.get("cognito.scopes.prefixes"));
                System.out.println("Contagem: " + result.get("cognito.scopes.count"));
                System.out.println("Última atualização: " + result.get("cognito.scopes.last_updated"));
                System.out.println("Cache hit: " + result.get("cognito.scopes.cache_hit"));
                System.out.println("Input processado: " + result.get("cognito.scopes.input_processed"));
                System.out.println("Input mapeado: " + result.get("cognito.scopes.input_mapped"));
            }
            
        } catch (Exception e) {
            System.err.println("Erro durante o teste: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
