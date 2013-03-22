/**
 * 
 */
package com.smartupz.tigase.auth.oauth;

import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

/**
 * @author zgoda
 *
 */
public class OauthSaslServerFactory implements SaslServerFactory {

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServerFactory#createSaslServer(java.lang.String, java.lang.String, java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
	 */
	@Override
	public SaslServer createSaslServer(final String mechanism, String protocol, String serverName,
			Map<String, ?> props, CallbackHandler callbackHandler) throws SaslException {
		// TODO Auto-generated method stub
		if (mechanism.equals("OAUTH")) {
			return new SaslOAUTH(props, callbackHandler);
		} else
			throw new SaslException("Mechanism not supported.");
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServerFactory#getMechanismNames(java.util.Map)
	 */
	@Override
	public String[] getMechanismNames(Map<String, ?> arg0) {
		// TODO Auto-generated method stub
		return null;
	}

}
