package com.smartupz.tigase.auth.oauth;

import javax.security.sasl.SaslServerFactory;

import tigase.auth.DefaultMechanismSelector;
import tigase.xmpp.XMPPResourceConnection;

public class OAuthEnabledMechanismSelector extends DefaultMechanismSelector {

	protected boolean match(SaslServerFactory factory, String mechanismName, XMPPResourceConnection session) {
		boolean result = super.match(factory, mechanismName, session);
		if (!result && (factory instanceof OAuthSaslServerFactory)) {
			return true;
		}
		return result;
	}
	
}
