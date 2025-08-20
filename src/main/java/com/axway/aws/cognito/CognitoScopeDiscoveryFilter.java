package com.axway.aws.cognito;

import com.vordel.circuit.DefaultFilter;
import com.vordel.common.util.PropDef;
import com.vordel.config.ConfigContext;
import com.vordel.es.EntityStoreException;
import com.vordel.mime.Body;
import com.vordel.mime.HeaderSet;

public class CognitoScopeDiscoveryFilter extends DefaultFilter {

	@Override
	protected final void setDefaultPropertyDefs() {
		// Request properties (input fields)
		this.reqProps.add(new PropDef("userPoolId", String.class));
		this.reqProps.add(new PropDef("clientId", String.class));
		this.reqProps.add(new PropDef("awsRegion", String.class));
		this.reqProps.add(new PropDef("credentialType", String.class));
		this.reqProps.add(new PropDef("awsCredential", String.class));
		this.reqProps.add(new PropDef("clientConfiguration", String.class));
		this.reqProps.add(new PropDef("credentialsFilePath", String.class));
		this.reqProps.add(new PropDef("scopesInput", String.class));
		
		// Generated properties (output fields)
		this.genProps.add(new PropDef("cognito.scopes.available",String.class));
		this.genProps.add(new PropDef("cognito.scopes.mapped",String.class));
		this.genProps.add(new PropDef("cognito.scopes.prefixes",String.class));
		this.genProps.add(new PropDef("cognito.scopes.count",Integer.class));
		this.genProps.add(new PropDef("cognito.scopes.input_processed",String.class));
		this.genProps.add(new PropDef("cognito.scopes.input_mapped",String.class));
		this.genProps.add(new PropDef("cognito.scopes.cache_hit",Boolean.class));
		this.genProps.add(new PropDef("cognito.scopes.last_updated",String.class));
		
		// Output fields for UI display
		this.genProps.add(new PropDef("outputScopesAvailable",String.class));
		this.genProps.add(new PropDef("outputScopesMapped",String.class));
		this.genProps.add(new PropDef("outputScopesPrefixes",String.class));
		this.genProps.add(new PropDef("outputScopesCount",Integer.class));
		this.genProps.add(new PropDef("outputScopesInputProcessed",String.class));
		this.genProps.add(new PropDef("outputScopesInputMapped",String.class));
		this.genProps.add(new PropDef("outputCacheHit",Boolean.class));
		this.genProps.add(new PropDef("outputLastUpdated",String.class));
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
