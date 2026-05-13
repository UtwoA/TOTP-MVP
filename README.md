# RADIUS TOTP 2FA MVP

Демонстрационный MVP двухфакторной аутентификации для удалённого доступа через RADIUS.

Решение показывает основной сценарий:

```text
RADIUS-запрос
    ↓
Проверка пароля пользователя
    ↓
Проверка TOTP-кода
    ↓
Access-Accept / Access-Reject
```

В демонстрационном стенде используется локальный password backend без Microsoft Active Directory. В production-режиме этот backend может быть заменён на Microsoft AD/LDAPS.

## Возможности MVP

- RADIUS `Access-Accept`, `Access-Reject`, `Access-Challenge`.
- Проверка TOTP-кодов по RFC 6238.
- Совместимость с Google Authenticator и Яндекс Ключом.
- Enrollment пользователя через CLI.
- Генерация OTP URI и QR-кода.
- Хранение TOTP-секрета в зашифрованном виде.
- Защита от повторного использования TOTP timestep.
- Audit log успешных и неуспешных попыток.
- PostgreSQL-хранилище пользователей и событий.

## Демонстрационный Стенд

```text
Тестовый клиент
    ↓ RADIUS UDP/1812
VPS 185.216.71.170
    ↓
RADIUS TOTP Service
    ↓
PostgreSQL
    ↓
TOTP Verification
    ↓
Access-Accept / Access-Reject
```

Компоненты стенда:

- VPS: `185.216.71.170`;
- RADIUS-сервис: `radius-totp-service`;
- база данных: PostgreSQL в Docker;
- тестовый пользователь: `demo.user`;
- тестовый пароль: `DemoPassword123`;
- authenticator-приложение: Google Authenticator или Яндекс Ключ.

## Демонстрационный Протокол

### 1. Старт RADIUS-Сервиса

```console
root@VPS-utwoa:/opt/radius-totp# cd /opt/radius-totp
root@VPS-utwoa:/opt/radius-totp# docker compose -f docker-compose.vps.yml logs --tail=30 radius-totp
radius-totp-service  | 2026-05-13 16:18:35,904 INFO radius_totp.radius_server Starting RADIUS server on 0.0.0.0:1812
```

Логи подтверждают, что RADIUS-сервис запущен и слушает сетевые запросы на UDP-порту `1812`.

### 2. Регистрация Пользователя В 2FA

```console
root@VPS-utwoa:/opt/radius-totp# cd /opt/radius-totp
root@VPS-utwoa:/opt/radius-totp# docker compose -f docker-compose.vps.yml exec radius-totp radius-totp reset demo.user
2FA reset for demo.user
root@VPS-utwoa:/opt/radius-totp# docker compose -f docker-compose.vps.yml exec radius-totp radius-totp enroll demo.user --qr-path /tmp/demo.user.png
OTP URI: otpauth://totp/Demo%20VPN:demo.user?secret=W65DG2X5I5AKETKBCQSYYIKH7QKLDKGV&issuer=Demo%20VPN
QR code written to: /tmp/demo.user.png
Enter test OTP code:
2FA enabled for demo.user
```

На этом шаге сервис генерирует TOTP secret, формирует OTP URI/QR-код и включает 2FA только после подтверждения тестовым кодом.

### 3. Проверка Состояния Пользователя В Базе

```console
root@VPS-utwoa:/opt/radius-totp# cd /opt/radius-totp
root@VPS-utwoa:/opt/radius-totp# docker compose -f docker-compose.vps.yml exec postgres psql -U radius_totp -d radius_totp -c "SELECT username, is_enabled, last_used_timestep, secret_encrypted IS NOT NULL AS has_secret FROM users;"
 username  | is_enabled | last_used_timestep | has_secret
-----------+------------+--------------------+------------
 demo.user | t          |                    | t
(1 row)
```

Запись в БД показывает, что пользователь включён в 2FA, secret сохранён и не отображается открытым текстом.

### 4. Успешная RADIUS-Аутентификация

```console
PS C:\TOTP> radius-totp test-radius --server 185.216.71.170 --secret shared-secret --username demo.user --password DemoPassword123 --otp 468353
Access-Accept
Reply-Message: Access granted
```

Корректный пароль и актуальный TOTP-код дают доступ, после чего RADIUS-сервис возвращает `Access-Accept`.

### 5. Отказ При Неверном OTP

```console
PS C:\TOTP> radius-totp test-radius --server 185.216.71.170 --secret shared-secret --username demo.user --password DemoPassword123 --otp 000000
Access-Reject
Reply-Message: Access denied
```

Неверный TOTP-код блокирует доступ, а RADIUS-сервис возвращает `Access-Reject`.

### 6. Защита От Повторного Использования OTP

```console
PS C:\TOTP> radius-totp test-radius --server 185.216.71.170 --secret shared-secret --username demo.user --password DemoPassword123 --otp 123540
Access-Accept
Reply-Message: Access granted
PS C:\TOTP> radius-totp test-radius --server 185.216.71.170 --secret shared-secret --username demo.user --password DemoPassword123 --otp 123540
Access-Reject
Reply-Message: Access denied
```

Первый запрос с актуальным TOTP-кодом проходит успешно. Повторное использование уже принятого кода блокируется.

### 7. Audit Log

```console
root@VPS-utwoa:/opt/radius-totp# cd /opt/radius-totp
root@VPS-utwoa:/opt/radius-totp# docker compose -f docker-compose.vps.yml exec postgres psql -U radius_totp -d radius_totp -c "SELECT created_at, username, result, reason, radius_client FROM auth_logs ORDER BY created_at DESC LIMIT 10;"
          created_at           | username  | result |    reason    | radius_client
-------------------------------+-----------+--------+--------------+---------------
 2026-05-13 16:20:09.38326+00  | demo.user | reject | reused_totp  | test-client
 2026-05-13 16:20:08.107964+00 | demo.user | accept | ok           | test-client
 2026-05-13 16:19:53.453936+00 | demo.user | reject | invalid_totp | test-client
 2026-05-13 16:19:40.151656+00 | demo.user | accept | ok           | test-client
 2026-05-13 16:19:14.133338+00 | demo.user | accept | enroll_ok    |
 2026-05-13 16:18:56.028299+00 | demo.user | accept | reset        |
 2026-05-13 16:00:34.326935+00 | demo.user | accept | ok           | test-client
 2026-05-13 15:49:11.888833+00 | demo.user | accept | enroll_ok    |
(8 rows)
```

Audit log фиксирует регистрацию, успешные входы, неверный OTP и повторное использование уже принятого OTP-кода.

## Подтверждённые Возможности MVP

- RADIUS-сервис запускается как отдельный сервис.
- Пользователь регистрируется через CLI.
- QR/OTP URI совместим с Google Authenticator и Яндекс Ключом.
- Секрет пользователя хранится в зашифрованном виде.
- Корректный пароль и корректный OTP дают `Access-Accept`.
- Неверный OTP даёт `Access-Reject`.
- Повторное использование OTP даёт `Access-Reject`.
- Все попытки фиксируются в audit log.
- Решение работает на уровне RADIUS и не зависит от конкретного VPN-клиента.

## Ограничения Демонстрационного Стенда

- В демо используется локальный password backend.
- Microsoft AD/LDAPS не подключался на данном стенде.
- Web-интерфейс администратора не входит в MVP.
- Recovery-коды не входят в MVP.
- Кластеризация и отказоустойчивость не входят в MVP.
- SIEM-интеграция не входит в MVP.
