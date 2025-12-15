package ru.mtuci.coursemanagement.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.net.URI;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.List;

@Slf4j
@Component
public class PluginLoader {
    // Исправлено: Remote Code Execution - валидация URL для предотвращения загрузки классов с произвольных URL
    private static final List<String> ALLOWED_SCHEMES = Arrays.asList("file");
    private static final List<String> BLOCKED_HOSTS = Arrays.asList("localhost", "127.0.0.1", "0.0.0.0", "::1");

    @Value("${app.plugin.url:}")
    private String pluginUrl;

    public void tryLoad() {
        if (pluginUrl == null || pluginUrl.isBlank()) return;
        try {
            URI uri = new URI(pluginUrl);

            if (!ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())) {
                log.error("Plugin loading blocked: only file:// scheme is allowed");
                return;
            }

            String host = uri.getHost();
            if (host != null && BLOCKED_HOSTS.contains(host.toLowerCase())) {
                log.error("Plugin loading blocked: access to internal hosts is not allowed");
                return;
            }

            if (host != null && (host.startsWith("169.254.") || host.startsWith("10.") ||
                    host.startsWith("172.16.") || host.startsWith("192.168."))) {
                log.error("Plugin loading blocked: access to private network addresses is not allowed");
                return;
            }

            URL url = uri.toURL();
            try (URLClassLoader cl = new URLClassLoader(new URL[]{url}, this.getClass().getClassLoader())) {
                Class<?> clazz = Class.forName("com.example.PluginMain", true, cl);
                Method m = clazz.getDeclaredMethod("init");
                m.setAccessible(false);
                m.invoke(null);
                log.info("Плагин загружен с URL: {}", pluginUrl);
            }
        } catch (Exception e) {
            log.error("Ошибка загрузки плагина: ", e);
        }
    }
}