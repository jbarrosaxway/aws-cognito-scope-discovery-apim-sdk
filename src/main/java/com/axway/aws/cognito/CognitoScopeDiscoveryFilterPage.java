package com.axway.aws.cognito;

import org.eclipse.swt.widgets.Composite;
import com.vordel.client.manager.wizard.VordelPage;

/**
 * Página de configuração para o filtro de descoberta de scopes do Cognito
 */
public class CognitoScopeDiscoveryFilterPage extends VordelPage {
    
    public CognitoScopeDiscoveryFilterPage() {
        super("AWSCognitoScopeDiscoveryPage");
        setTitle(resolve("AWS_COGNITO_SCOPE_DISCOVERY_PAGE"));
        setDescription(resolve("AWS_COGNITO_SCOPE_DISCOVERY_PAGE_DESCRIPTION"));
        setPageComplete(true);
    }
    
    public String getHelpID() {
        return "com.vordel.rcp.policystudio.filter.help.aws_cognito_scope_discovery_filter_help";
    }
    
    public boolean performFinish() {
        return true;
    }
    
    public void createControl(Composite parent) {
        Composite panel = render(parent, getClass().getResourceAsStream("cognito_scope_discovery.xml"));
        setControl(panel);
        setPageComplete(true);
    }
}
