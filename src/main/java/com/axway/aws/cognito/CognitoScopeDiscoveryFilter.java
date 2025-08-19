package com.axway.aws.cognito;

/**
 * Filtro para descoberta de scopes do AWS Cognito
 * 
 * Esta classe define as propriedades e configurações do filtro
 * para descoberta dinâmica de scopes do Cognito.
 */
public class CognitoScopeDiscoveryFilter {

    // Propriedades de entrada
    public static final String PROP_USER_POOL_ID = "userPoolId";
    public static final String PROP_CLIENT_ID = "clientId";
    public static final String PROP_AWS_REGION = "awsRegion";
    public static final String PROP_CREDENTIAL_TYPE = "credentialType";
    public static final String PROP_AWS_CREDENTIAL = "awsCredential";
    public static final String PROP_CREDENTIALS_FILE_PATH = "credentialsFilePath";
    public static final String PROP_CLIENT_CONFIGURATION = "clientConfiguration";
    public static final String PROP_SCOPES_INPUT = "scopesInput";

    // Propriedades de saída
    public static final String PROP_SCOPES_AVAILABLE = "cognito.scopes.available";
    public static final String PROP_SCOPES_MAPPED = "cognito.scopes.mapped";
    public static final String PROP_SCOPES_PREFIXES = "cognito.scopes.prefixes";
    public static final String PROP_SCOPES_COUNT = "cognito.scopes.count";
    public static final String PROP_SCOPES_INPUT_PROCESSED = "cognito.scopes.input_processed";
    public static final String PROP_SCOPES_INPUT_MAPPED = "cognito.scopes.input_mapped";
    public static final String PROP_SCOPES_ERROR = "cognito.scopes.error";
    public static final String PROP_SCOPES_ERROR_DESCRIPTION = "cognito.scopes.error_description";
    public static final String PROP_SCOPES_CACHE_HIT = "cognito.scopes.cache_hit";
    public static final String PROP_SCOPES_LAST_UPDATED = "cognito.scopes.last_updated";

    /**
     * Obtém o nome do filtro
     */
    public String getFilterName() {
        return "AWS Cognito Scope Discovery Filter";
    }

    /**
     * Obtém a descrição do filtro
     */
    public String getFilterDescription() {
        return "Descobre dinamicamente scopes disponíveis no AWS Cognito para um determinado clientId";
    }

    /**
     * Obtém a categoria do filtro
     */
    public String getFilterCategory() {
        return "AWS Cognito";
    }
}
