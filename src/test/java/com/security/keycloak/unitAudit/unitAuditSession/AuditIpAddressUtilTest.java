package com.security.keycloak.unitAudit.unitAuditSession;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import jakarta.servlet.http.HttpServletRequest;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.security.keycloak.audit.message.util.IpAddressUtil;

class AuditIpAddressUtilTest {

    private IpAddressUtil ipAddressUtil;
    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        ipAddressUtil = new IpAddressUtil();
        request = mock(HttpServletRequest.class);
    }

    @Test
    @DisplayName("getClientIpAddress - debe tomar la IP desde X-Forwarded-For")
    void getClientIpAddress_xForwardedFor() {
        when(request.getHeader("X-Forwarded-For"))
                .thenReturn("190.10.20.30");

        String result = ipAddressUtil.getClientIpAddress(request);

        assertEquals("190.10.20.30", result);
    }

    @Test
    @DisplayName("getClientIpAddress - debe tomar la primera IP si el header trae varias")
    void getClientIpAddress_variasIps() {
        when(request.getHeader("X-Forwarded-For"))
                .thenReturn("190.10.20.30, 10.0.0.1, 172.16.0.1");

        String result = ipAddressUtil.getClientIpAddress(request);

        assertEquals("190.10.20.30", result);
    }

    @Test
    @DisplayName("getClientIpAddress - debe hacer trim a la IP")
    void getClientIpAddress_trim() {
        when(request.getHeader("X-Forwarded-For"))
                .thenReturn("   190.10.20.30   ");

        String result = ipAddressUtil.getClientIpAddress(request);

        assertEquals("190.10.20.30", result);
    }

    @Test
    @DisplayName("getClientIpAddress - ignora header unknown y usa siguiente header válido")
    void getClientIpAddress_ignoraUnknown() {
        when(request.getHeader("X-Forwarded-For"))
                .thenReturn("unknown");
        when(request.getHeader("Proxy-Client-IP"))
                .thenReturn("181.50.60.70");

        String result = ipAddressUtil.getClientIpAddress(request);

        assertEquals("181.50.60.70", result);
    }

    @Test
    @DisplayName("getClientIpAddress - ignora header vacío y usa siguiente header válido")
    void getClientIpAddress_ignoraVacio() {
        when(request.getHeader("X-Forwarded-For"))
                .thenReturn("   ");
        when(request.getHeader("Proxy-Client-IP"))
                .thenReturn("181.50.60.70");

        String result = ipAddressUtil.getClientIpAddress(request);

        assertEquals("181.50.60.70", result);
    }

    @Test
    @DisplayName("getClientIpAddress - si no hay headers válidos usa remoteAddr")
    void getClientIpAddress_usaRemoteAddr() {
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");

        String result = ipAddressUtil.getClientIpAddress(request);

        assertEquals("127.0.0.1", result);
    }
}
