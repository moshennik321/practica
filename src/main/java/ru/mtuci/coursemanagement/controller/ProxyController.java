package ru.mtuci.coursemanagement.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

@RestController
public class ProxyController {
    // Исправлено: SSRF (Server-Side Request Forgery) - валидация URL и whitelist разрешенных схем
    private static final List<String> ALLOWED_SCHEMES = Arrays.asList("http", "https");
    private static final List<String> BLOCKED_HOSTS = Arrays.asList("localhost", "127.0.0.1", "0.0.0.0", "::1");

    @GetMapping("/api/proxy")
    public ResponseEntity<String> proxy(@RequestParam("targetUrl") String targetUrl) {
        try {
            URI uri = new URI(targetUrl);

            if (!ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Only HTTP and HTTPS schemes are allowed");
            }

            String host = uri.getHost();
            if (host == null || BLOCKED_HOSTS.contains(host.toLowerCase())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Access to internal hosts is not allowed");
            }

            if (host.startsWith("169.254.") || host.startsWith("10.") ||
                    host.startsWith("172.16.") || host.startsWith("192.168.")) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body("Access to private network addresses is not allowed");
            }

            RestTemplate rt = new RestTemplate();
            String result = rt.getForObject(uri.toURL().toString(), String.class);
            return ResponseEntity.ok(result);
        } catch (URISyntaxException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Invalid URL format");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error processing request");
        }
    }
}
