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
		this.reqProps.add(new PropDef("content.body", Body.class));
		this.reqProps.add(new PropDef("http.headers", HeaderSet.class));
		genProps.add(new PropDef("cognito.scopes.available",String.class));
		genProps.add(new PropDef("cognito.scopes.mapped",String.class));
		genProps.add(new PropDef("cognito.scopes.prefixes",String.class));
		genProps.add(new PropDef("cognito.scopes.count",Integer.class));
		genProps.add(new PropDef("cognito.scopes.input_processed",String.class));
		genProps.add(new PropDef("cognito.scopes.input_mapped",String.class));
		genProps.add(new PropDef("cognito.scopes.cache_hit",Boolean.class));
		genProps.add(new PropDef("cognito.scopes.last_updated",String.class));
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
