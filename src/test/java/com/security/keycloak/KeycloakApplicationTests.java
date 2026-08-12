package com.security.keycloak;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
		"KEYCLOAK_ISSUER_URI=http://localhost/test/realms/oauth2-realm",
		"KEYCLOAK_JWK_SET_URI=http://localhost/test/realms/oauth2-realm/protocol/openid-connect/certs",
		"PRINCIPLE_ATTRIBUTE=preferred_username",
		"RESOURCE_ID=microservices_client",
		"JWT_PUBLIC_KEY=test-public-key",
		"JWT_TOKEN_URL=http://localhost/test/token",
		"KEYCLOAK_ADMIN=test-admin",
		"KEYCLOAK_PASSWORD=test-password",
		"KEYCLOAK_USER_CONSOLE=test-console",
		"KEYCLOAK_CLIENT_SECRET=test-client-secret",
		"KEYCLOAK_SERVER_URL=http://localhost/test",
		"KEYCLOAK_REALM_NAME=oauth2-realm",
		"KEYCLOAK_REALM_MASTER=master",
		"eureka.client.enabled=false"
})
class KeycloakApplicationTests {

	@Test
	void contextLoads() {
	}

}
