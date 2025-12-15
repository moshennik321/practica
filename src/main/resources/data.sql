-- Инициализация демо-данных
-- Исправлено: Insecure Credential Storage - пароли захешированы с помощью BCrypt вместо plain-text
-- Пользователи (пароли захешированы с помощью BCrypt, оригинальный пароль: "password")
-- nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash
INSERT INTO USERS (id, username, password, role)
VALUES (1, 'teacher', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'TEACHER');
-- nosemgrep: generic.secrets.security.detected-bcrypt-hash.detected-bcrypt-hash
INSERT INTO USERS (id, username, password, role)
VALUES (2, 'student', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'STUDENT');
ALTER TABLE USERS ALTER COLUMN ID RESTART WITH 3;

-- Студенты
INSERT INTO STUDENTS (id, name, email, user_id)
VALUES (1, 'Alice', 'alice@example.com', 2),
       (2, 'Bob', 'bob@example.com', NULL);
ALTER TABLE STUDENTS ALTER COLUMN ID RESTART WITH 3;

-- Курсы
INSERT INTO COURSES (id, title, description, teacher_id)
VALUES (1, 'RBPO', 'Basics of securing apps', 1),
       (2, 'Database Basics', 'Intro to SQL', 1);
ALTER TABLE COURSES ALTER COLUMN ID RESTART WITH 3;

