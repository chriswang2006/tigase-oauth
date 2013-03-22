package com.smartupz.tigase.auth.oauth;

import java.util.HashMap;
import java.util.Map;

import javax.security.sasl.SaslException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.harlap.test.http.MockHttpServer;

import tigase.auth.XmppSaslException;

import junit.framework.TestCase;

public class SaslOAUTHTest extends TestCase {
	
	private SaslOAUTH sasl;
	private static final int PORT = 8082;
	private static final String baseUrl = "http://localhost:" + PORT;
	private MockHttpServer oauthServer;
	private static final String KNOWN_USER_JSON = "{\"object\":{\"uuid\":\"user#1\"}}";
	private static final String UNKNOWN_USER_RESPONSE = "Authentication error.";
	
	@Before
	public void setUp() throws Exception {
		oauthServer = new MockHttpServer(PORT);
		oauthServer.start();
		Map<String, String> props = new HashMap<String, String>();
		props.put("server-url", baseUrl + "/profile");
		this.sasl = new SaslOAUTH(props, null);
	}
	
	@After
	public void tearDown() throws Exception {
		oauthServer.stop();
	}

	@Test
	public void testKnownUser() {
		oauthServer.expect(MockHttpServer.Method.GET, "/profile").respondWith(200, "application/json", KNOWN_USER_JSON);
		try {
			sasl.evaluateResponse("\0user#1\0".getBytes());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
		assertTrue(sasl.isComplete());
		assertEquals("user#1", sasl.getAuthorizationID());
	}

	@Test
	public void testUnknownUser() {
		oauthServer.expect(MockHttpServer.Method.GET, "/profile").respondWith(401, "text/plain", UNKNOWN_USER_RESPONSE);
		try {
			sasl.evaluateResponse("\0joe\0".getBytes());
			fail("Exception has to be thrown");
		} catch (XmppSaslException e) {
			assertEquals("not-authorized", e.getSaslErrorElementName());
		} catch (SaslException e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	@Test
	public void testOAuthServerDown() throws Exception {
		oauthServer.stop();
		try {
			sasl.evaluateResponse("\0user#1\0".getBytes());
			fail("Exception has to be thrown");
		} catch (XmppSaslException e) {
			assertEquals("temporary-auth-failure", e.getSaslErrorElementName());
		} catch (SaslException e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

}
