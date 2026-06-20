package com.security.keycloak.audit.message.util;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

@Component
public class IpAddressUtil {

    private static final String[] IP_HEADER_CANDIDATES = {
            "X-Forwarded-For",
            "Proxy-Client-IP",
            "WL-Proxy-Client-IP",
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_FORWARDED",
            "HTTP_X_CLUSTER_CLIENT_IP",
            "HTTP_CLIENT_IP",
            "HTTP_FORWARDED_FOR",
            "HTTP_VIA",
            "REMOTE_ADDR"
    };

    public String getClientIpAddress(HttpServletRequest request) {

        for (String header : IP_HEADER_CANDIDATES) {
            String ipList = request.getHeader(header);
            if (StringUtils.hasText(ipList) && !"unknown".equalsIgnoreCase(ipList)) {
                String ip = ipList.split(",")[0].trim();
                return ip;
            }
        }
        String ip = request.getRemoteAddr();
        return ip;
    }
}
