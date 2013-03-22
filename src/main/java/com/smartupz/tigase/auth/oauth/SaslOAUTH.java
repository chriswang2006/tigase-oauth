/**
 * 
 */
package com.smartupz.tigase.auth.oauth;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.SaslException;

import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Verb;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import tigase.auth.XmppSaslException;
import tigase.auth.XmppSaslException.SaslError;
import tigase.auth.mechanisms.AbstractSasl;

/**
 * @author zgoda
 *
 */
public class SaslOAUTH extends AbstractSasl {
	
	private static final String MECHANISM = "OAUTH";
	
	private String oauthServerUrl;

	protected SaslOAUTH(Map<? super String, ?> props,
			CallbackHandler callbackHandler) {
		super(props, callbackHandler);
		setOauthServerUrl((String) props.get("server-url"));
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#evaluateResponse(byte[])
	 */
	@Override
	public byte[] evaluateResponse(byte[] response) throws SaslException {
		String userId;
		try {
			if (response != null && response.length > 0) {
				OAuthRequest rq = new OAuthRequest(Verb.GET, getOauthServerUrl());
				rq.addHeader("Bearer", new String(response));
				Response oauthResponse = rq.send();
				ObjectMapper mapper = new ObjectMapper();
				HashMap<?, ?> x = mapper.readValue(oauthResponse.getBody(), HashMap.class);
				userId = (String) x.get("uuid");
			} else {
				userId = null;
			}
		} catch (JsonParseException e) {
			throw new XmppSaslException(SaslError.malformed_request);
		} catch (JsonMappingException e) {
			throw new XmppSaslException(SaslError.malformed_request);
		} catch (IOException e) {
			throw new XmppSaslException(SaslError.temporary_auth_failure);
		}
		if (userId != null) {
			authorizedId = userId;
		} else {
			throw new XmppSaslException(SaslError.invalid_authzid);
		}
		complete = true;
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#getAuthorizationID()
	 */
	@Override
	public String getAuthorizationID() {
		return authorizedId;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#getMechanismName()
	 */
	@Override
	public String getMechanismName() {
		return MECHANISM;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#unwrap(byte[], int, int)
	 */
	@Override
	public byte[] unwrap(byte[] incoming, int offset, int len) throws SaslException {
		return null;
	}

	/* (non-Javadoc)
	 * @see javax.security.sasl.SaslServer#wrap(byte[], int, int)
	 */
	@Override
	public byte[] wrap(byte[] outgoing, int offset, int len) throws SaslException {
		return null;
	}

	public String getOauthServerUrl() {
		return oauthServerUrl;
	}

	public void setOauthServerUrl(String oauthServerUrl) {
		this.oauthServerUrl = oauthServerUrl;
	}

}
