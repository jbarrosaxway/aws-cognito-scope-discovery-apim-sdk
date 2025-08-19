package com.axway.aws.cognito;

import com.vordel.circuit.DefaultFilter;
import com.vordel.common.util.PropDef;
import com.vordel.config.ConfigContext;
import com.vordel.es.EntityStoreException;
import com.vordel.mime.Body;
import com.vordel.mime.HeaderSet;

/**
 * Filtro para descoberta dinâmica de scopes do AWS Cognito
 * 
 * Este filtro consulta o Cognito para descobrir automaticamente quais scopes
 * estão disponíveis para um determinado clientId, eliminando a necessidade
 * de mapeamentos fixos de scopes.
 */
public class CognitoScopeDiscoveryFilter extends DefaultFilter {

    @Override
    protected final void setDefaultPropertyDefs() {
        // Propriedades de entrada
        this.reqProps.add(new PropDef("content.body", Body.class));
        this.reqProps.add(new PropDef("http.headers", HeaderSet.class));
        this.reqProps.add(new PropDef("cognito.scopes.input", String.class));
        
        // Propriedades geradas
        this.genProps.add(new PropDef("cognito.scopes.available", String.class));
        this.genProps.add(new PropDef("cognito.scopes.mapped", String.class));
        this.genProps.add(new PropDef("cognito.scopes.prefixes", String.class));
        this.genProps.add(new PropDef("cognito.scopes.count", Integer.class));
        this.genProps.add(new PropDef("cognito.scopes.input_processed", String.class));
        this.genProps.add(new PropDef("cognito.scopes.input_mapped", String.class));
        this.genProps.add(new PropDef("cognito.scopes.error", String.class));
        this.genProps.add(new PropDef("cognito.scopes.error_description", String.class));
        this.genProps.add(new PropDef("cognito.scopes.cache_hit", Boolean.class));
        this.genProps.add(new PropDef("cognito.scopes.last_updated", String.class));
    }

    @Override
    public void configure(ConfigContext ctx, com.vordel.es.Entity entity) throws EntityStoreException {
        super.configure(ctx, entity);
    }

    @Override
    public Class<CognitoScopeDiscoveryProcessor> getMessageProcessorClass() {
        return CognitoScopeDiscoveryProcessor.class;
    }

    public Class getConfigPanelClass() throws ClassNotFoundException {
        // Avoid any compile or runtime dependencies on SWT and other UI
        // libraries by lazily loading the class when required.
        return Class.forName("com.axway.aws.cognito.CognitoScopeDiscoveryFilterUI");
    }
}
