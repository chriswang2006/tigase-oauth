/**
 * 
 */
package com.smartupz.tigase.auth.oauth;

import java.util.Map;
import java.util.logging.Logger;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;

import tigase.auth.TigaseSaslProvider;

/**
 * @author zgoda
 *
 */
public class OauthSaslServerFactory implements SaslServerFactory {

	private static final Logger log = Logger.getLogger(OauthSaslServerFactory.class.getName());
	
	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServerFactory#createSaslServer(java.lang.String, java.lang.String, java.lang.String, java.util.Map, javax.security.auth.callback.CallbackHandler)
	 */
	@Override
	public SaslServer createSaslServer(final String mechanism, String protocol, String serverName,
			Map<String, ?> props, CallbackHandler callbackHandler) throws SaslException {
		log.config("Creating instance of SASL: " + mechanism);
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
		return new String[] { "OAUTH" };
	}

}
