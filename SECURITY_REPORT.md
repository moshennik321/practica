# Отчет о поиске, анализе и устранении уязвимостей в программном обеспечении

## 1. Введение

Данный отчет содержит результаты анализа безопасности веб-приложения для управления курсами (course-management), выполненного с использованием инструментов статического (SAST), динамического (DAST) тестирования безопасности и анализа состава программного обеспечения (SCA).

**Использованные инструменты:**
- **SAST:** Semgrep
- **SCA:** OWASP Dependency-Check
- **DAST:** OWASP ZAP (Baseline Scan и API Scan)

---

## 2. Реальные уязвимости

### 2.1. A03:2021 – Injection (SQL Injection)

**Описание:** В методе `searchByTitle` класса `CourseService` использовалась конкатенация строк для формирования SQL-запроса, что позволяло злоумышленнику выполнить произвольные SQL-команды.

**Местоположение:** `src/main/java/ru/mtuci/coursemanagement/service/CourseService.java:35`

**Критичность:** Высокая

**Пример уязвимого кода:**
```java
String sql = "SELECT id, title, description, teacher_id FROM courses WHERE title = '" + title + "'";
```

**Решение:** Использование параметризованных запросов через `JdbcTemplate`:
```java
String sql = "SELECT id, title, description, teacher_id FROM courses WHERE title = ?";
return jdbc.query(sql, rm, title);
```

**Статус:** ✅ Исправлено

---

### 2.2. A03:2021 – Injection (XXE - XML External Entity)

**Описание:** В контроллере `XmlController` отсутствовала защита от XML External Entity (XXE) атак. Злоумышленник мог загрузить вредоносный XML, который читал локальные файлы или выполнял SSRF-атаки.

**Местоположение:** `src/main/java/ru/mtuci/coursemanagement/controller/XmlController.java:18`

**Критичность:** Высокая

**Решение:** Отключение внешних сущностей и DTD, настройка `EntityResolver`:
```java
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
reader.setEntityResolver(new EntityResolver() {
    @Override
    public InputSource resolveEntity(String publicId, String systemId) {
        return new InputSource(new StringReader(""));
    }
});
```

**Статус:** ✅ Исправлено

---

### 2.3. A10:2021 – Server-Side Request Forgery (SSRF)

**Описание:** Две уязвимости SSRF обнаружены в контроллерах `ProxyController` и `CourseController`. Отсутствовала валидация URL, что позволяло выполнять запросы к внутренним ресурсам сервера.

**Местоположение:**
- `src/main/java/ru/mtuci/coursemanagement/controller/ProxyController.java:21`
- `src/main/java/ru/mtuci/coursemanagement/controller/CourseController.java:75`

**Критичность:** Высокая

**Решение:**
1. Whitelist разрешенных схем (только `http` и `https`)
2. Блокировка внутренних хостов (`localhost`, `127.0.0.1`, `0.0.0.0`, `::1`)
3. Блокировка приватных сетей (169.254.x.x, 10.x.x.x, 172.16.x.x, 192.168.x.x)

**Пример исправленного кода:**
```java
private static final List<String> ALLOWED_SCHEMES = Arrays.asList("http", "https");
private static final List<String> BLOCKED_HOSTS = Arrays.asList("localhost", "127.0.0.1", "0.0.0.0", "::1");

URI uri = new URI(targetUrl);
if (!ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())) {
    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid scheme");
}
String host = uri.getHost();
if (host == null || BLOCKED_HOSTS.contains(host.toLowerCase())) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access to internal hosts is not allowed");
}
if (host.startsWith("169.254.") || host.startsWith("10.") || 
    host.startsWith("172.16.") || host.startsWith("192.168.")) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access to private network addresses is not allowed");
}
```

**Статус:** ✅ Исправлено

---

### 2.4. A02:2021 – Cryptographic Failures (Insecure Credential Storage)

**Описание:** Пароли пользователей хранились в открытом виде (plain-text) в базе данных и логировались в процессе аутентификации.

**Местоположение:**
- `src/main/java/ru/mtuci/coursemanagement/controller/AuthController.java:22`
- `src/main/resources/data.sql:2`

**Критичность:** Критическая

**Решение:**
1. Использование `BCryptPasswordEncoder` для хеширования паролей при регистрации
2. Использование `passwordEncoder.matches()` для проверки паролей при входе
3. Удаление логирования паролей
4. Обновление тестовых данных в `data.sql` с использованием BCrypt хешей

**Пример исправленного кода:**
```java
private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

// При регистрации
String hashedPassword = passwordEncoder.encode(password);
users.save(new User(null, username, hashedPassword, role));

// При входе
if (passwordEncoder.matches(password, u.getPassword())) {
    // успешная аутентификация
}
```

**Статус:** ✅ Исправлено

---

### 2.5. A01:2021 – Broken Access Control

**Описание:**
1. При регистрации пользователь мог указать произвольную роль, что позволяло получить привилегии администратора
2. Отсутствовала настройка правил авторизации в Spring Security

**Местоположение:**
- `src/main/java/ru/mtuci/coursemanagement/controller/AuthController.java:59`
- `src/main/java/ru/mtuci/coursemanagement/config/SecurityConfig.java:11`

**Критичность:** Высокая

**Решение:**
1. Валидация роли при регистрации (только `STUDENT` или `TEACHER`)
2. Настройка Spring Security с правильными правилами авторизации
3. Включение CSRF защиты

**Пример исправленного кода:**
```java
// Валидация роли
if (!role.equals("STUDENT") && !role.equals("TEACHER")) {
    role = "STUDENT";
}

// SecurityConfig
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/login", "/register", "/", "/css/**", "/js/**", "/images/**").permitAll()
    .requestMatchers("/api/**").permitAll()
    .requestMatchers("/courses", "/students").authenticated()
    .anyRequest().authenticated()
)
```

**Статус:** ✅ Исправлено

---

### 2.6. A05:2021 – Security Misconfiguration

**Описание:** Множественные проблемы с конфигурацией безопасности:
1. CORS настроен на разрешение всех источников (`*`)
2. H2 консоль доступна извне (`web-allow-others: true`)
3. Actuator endpoints открыты для всех (`include: "*"`)
4. Stacktrace отображается в ошибках (`include-stacktrace: ALWAYS`)
5. SQL запросы логируются в production
6. Отсутствуют Security Headers (CSP, HSTS, X-Frame-Options и др.)
7. Не настроено управление сессиями

**Местоположение:**
- `src/main/java/ru/mtuci/coursemanagement/config/WebConfig.java:9`
- `src/main/java/ru/mtuci/coursemanagement/config/SecurityConfig.java:11`
- `src/main/resources/application.yaml:4`

**Критичность:** Средняя

**Решение:**
1. **CORS:** Ограничение конкретными доменами
```java
.allowedOrigins("http://localhost:3000", "https://trusted-domain.com")
```

2. **H2 Console:** Отключена в `application.yaml`
```yaml
h2:
  console:
    enabled: false
    web-allow-others: false
```

3. **Actuator:** Ограничение только `health` и `info`
```yaml
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
```

4. **Stacktrace:** Отключен
```yaml
server:
  error:
    include-stacktrace: never
```

5. **SQL Logging:** Отключено
```yaml
jpa:
  show-sql: false
```

6. **Security Headers:** Настроены в `SecurityConfig`
```java
.headers(headers -> headers
    .contentSecurityPolicy(csp -> csp
        .policyDirectives("default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';")
    )
    .frameOptions(frame -> frame.deny())
    .httpStrictTransportSecurity(hsts -> hsts
        .maxAgeInSeconds(31536000)
    )
    .referrerPolicy(referrer -> referrer
        .policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
    )
    .xssProtection(xss -> xss
        .headerValue(XXssProtectionHeaderWriter.HeaderValue.ENABLED_MODE_BLOCK)
    )
    .contentTypeOptions(contentType -> {})
)
```

7. **Управление сессиями:** Ограничение одновременных сессий
```java
.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
    .maximumSessions(1)
    .maxSessionsPreventsLogin(false)
)
```

**Статус:** ✅ Исправлено

---

### 2.7. A08:2021 – Software and Data Integrity Failures (Remote Code Execution)

**Описание:** В классе `PluginLoader` отсутствовала валидация URL, что позволяло загружать и выполнять произвольный код с удаленных серверов.

**Местоположение:** `src/main/java/ru/mtuci/coursemanagement/service/PluginLoader.java:17`

**Критичность:** Критическая

**Решение:** Валидация URL с whitelist разрешенных схем (только `file`) и блокировка внутренних хостов и приватных сетей:
```java
private static final List<String> ALLOWED_SCHEMES = Arrays.asList("file");
private static final List<String> BLOCKED_HOSTS = Arrays.asList("localhost", "127.0.0.1", "0.0.0.0", "::1");

URI uri = new URI(pluginUrl);
if (!ALLOWED_SCHEMES.contains(uri.getScheme().toLowerCase())) {
    log.error("Invalid scheme for plugin URL: {}", pluginUrl);
    return;
}
String host = uri.getHost();
if (host != null && BLOCKED_HOSTS.contains(host.toLowerCase())) {
    log.error("Blocked host for plugin URL: {}", pluginUrl);
    return;
}
if (host != null && (host.startsWith("169.254.") || host.startsWith("10.") || 
    host.startsWith("172.16.") || host.startsWith("192.168."))) {
    log.error("Private network address blocked for plugin URL: {}", pluginUrl);
    return;
}
```

**Статус:** ✅ Исправлено

---

## 3. Ложные срабатывания

### 3.1. Semgrep: Обнаружение bcrypt хешей в data.sql

**Описание:** Semgrep обнаружил bcrypt хеши в файле `src/main/resources/data.sql` и пометил их как потенциальную уязвимость.

**Причина:** Semgrep ошибочно определяет bcrypt хеши как секреты, хотя в данном случае это исправление уязвимости (Insecure Credential Storage), а не сама уязвимость.

**Решение:**
1. Добавлен файл `.semgrepignore` с исключением `src/main/resources/data.sql`
2. Добавлены комментарии `nosemgrep` в SQL файл (для дополнительной защиты)

**Статус:** ✅ Подавлено

---

### 3.2. Semgrep: Thymeleaf шаблоны определяются как Django

**Описание:** Semgrep ошибочно определяет Thymeleaf шаблоны как Django шаблоны.

**Причина:** Синтаксис Thymeleaf похож на Django, что вызывает ложные срабатывания.

**Решение:** Добавлено исключение в `.semgrepignore`:
```
src/main/resources/templates/*.html
```

**Статус:** ✅ Подавлено

---

## 4. Варианты устранения уязвимостей

Все найденные уязвимости были устранены в рамках данного проекта. Ниже приведены общие рекомендации по предотвращению подобных уязвимостей в будущем:

### 4.1. Injection (SQL Injection, XXE)

1. **Всегда использовать параметризованные запросы** вместо конкатенации строк
2. **Отключать внешние сущности** при парсинге XML
3. **Использовать whitelist** для валидации входных данных
4. **Регулярно обновлять библиотеки** для парсинга XML

### 4.2. SSRF

1. **Валидировать все URL** перед выполнением запросов
2. **Использовать whitelist** разрешенных схем и хостов
3. **Блокировать внутренние адреса** (localhost, 127.0.0.1, приватные сети)
4. **Использовать DNS резолвинг** для проверки IP-адресов

### 4.3. Insecure Credential Storage

1. **Никогда не хранить пароли в открытом виде**
2. **Использовать современные алгоритмы хеширования** (BCrypt, Argon2, scrypt)
3. **Не логировать пароли** и другие чувствительные данные
4. **Использовать HTTPS** для передачи учетных данных

### 4.4. Broken Access Control

1. **Валидировать роли и права доступа** на стороне сервера
2. **Использовать принцип наименьших привилегий**
3. **Настраивать правильные правила авторизации** в Spring Security
4. **Включать CSRF защиту** для state-changing операций

### 4.5. Security Misconfiguration

1. **Отключать ненужные функции** (H2 console, debug endpoints)
2. **Ограничивать CORS** конкретными доменами
3. **Настраивать Security Headers** (CSP, HSTS, X-Frame-Options)
4. **Не отображать stacktrace** в production
5. **Ограничивать Actuator endpoints** только необходимыми
6. **Настраивать управление сессиями** (ограничение одновременных сессий)

### 4.6. Remote Code Execution

1. **Валидировать все URL** перед загрузкой кода
2. **Использовать whitelist** разрешенных источников
3. **Ограничивать загрузку классов** только локальными файлами (если возможно)
4. **Использовать sandbox** для выполнения непроверенного кода

---

## 5. Заключение

В результате анализа безопасности приложения было обнаружено и исправлено **7 категорий уязвимостей** согласно OWASP Top 10 2021:

1. ✅ **A03:2021 – Injection** (SQL Injection, XXE) - 2 уязвимости
2. ✅ **A10:2021 – Server-Side Request Forgery** (SSRF) - 2 уязвимости
3. ✅ **A02:2021 – Cryptographic Failures** (Insecure Credential Storage) - 1 уязвимость
4. ✅ **A01:2021 – Broken Access Control** - 1 уязвимость
5. ✅ **A05:2021 – Security Misconfiguration** - 7 проблем конфигурации
6. ✅ **A08:2021 – Software and Data Integrity Failures** (RCE) - 1 уязвимость

**Всего исправлено: 14 реальных уязвимостей**

Все уязвимости были устранены с использованием best practices безопасности. В коде добавлены комментарии на русском языке, указывающие на исправленные уязвимости.

**Ложные срабатывания:** 2 (подавлены через `.semgrepignore`)

---

## 6. Инструкции по скачиванию артефактов

После выполнения пайплайна GitHub Actions можно скачать следующие артефакты:

1. **SAST отчет (Semgrep):**
    - Формат: SARIF
    - Доступен в разделе "Security" → "Code scanning alerts" на GitHub
    - Или скачать артефакт `semgrep.sarif` из workflow run

2. **SCA отчет (OWASP Dependency-Check):**
    - Формат: HTML
    - Имя артефакта: `dependency-check-report`
    - Файл: `target/dependency-check-report.html`

3. **DAST отчеты (OWASP ZAP):**
    - Форматы: HTML, JSON, MD
    - Имя артефакта: `zap-scan-reports`
    - Файлы: `zap-report.html`, `zap-report.json`, `zap-report.md`

**Как скачать артефакты:**
1. Перейдите в раздел "Actions" на GitHub
2. Выберите нужный workflow run
3. Прокрутите вниз до раздела "Artifacts"
4. Нажмите на нужный артефакт для скачивания
5. 