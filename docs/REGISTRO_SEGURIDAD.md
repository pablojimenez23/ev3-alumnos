# Registro de seguridad · Sistema Alumnos

Estudiante: Pablo Andrés Jiménez Fredes   Repositorio: https://github.com/pablojimenez23/ev3-alumnos   Fecha: 27-11-2026

Cada fila se puede seguir hasta un **build de Jenkins** y un **commit** (identificadores `PIPE-xx`, `DEPS-xx` y `VULN-xx`
en los mensajes de commit). Las horas de los builds están en UTC (como las registra Jenkins); las del monitoreo, en hora de Chile (UTC-3).

### Pipeline implementado (Jenkinsfile)

| # | Etapa | Herramienta | Qué hace | Si encuentra algo |
|---|---|---|---|---|
| 1 | Build | Python venv, pip | Instala dependencias, compila y genera la versión `1.0.<build>+<commit>` | Falla el build |
| 2 | Test | pytest | 9 pruebas funcionales (reporte JUnit) | Falla el build |
| 3 | Security Review (SAST) | Bandit 1.8.6 | Análisis estático de `app.py` (`bandit.txt`, `bandit.json`) | Marca UNSTABLE (Medium/High) |
| 4 | Dependency Management | pip-audit 2.9.0 | Busca CVE conocidos en `requirements.txt` (`pip-audit.txt`, `pip-audit.json`) | Marca UNSTABLE |
| 5 | Deploy Staging | `scripts/deploy.sh` | Despliega en el puerto 5001 y hace prueba de humo | Falla el build |
| 6 | DAST - OWASP ZAP | OWASP ZAP 2.16.1 (API) | Spider + escaneo pasivo + escaneo activo sobre staging (`zap-report.html`) | Marca UNSTABLE (High/Medium) |
| 7 | Deploy Producción | `scripts/deploy.sh` | Despliega en el puerto 5000 | **Gate:** solo se ejecuta si el build está en SUCCESS |
| — | Post (siempre) | `scripts/trazabilidad.py` | Agrega una fila a `TRAZABILIDAD.md` y archiva todos los reportes | — |

Además: `pollSCM` cada ~3 min (cada push o PR fusionado dispara un build), Dependabot en GitHub y monitoreo con Prometheus + Grafana.

## 1. Revisiones de seguridad realizadas

| # | Etapa del SDLC | Herramienta / técnica | Build | Resultado (resumen) |
|---|---|---|---|---|
| R1 | Código (SAST) | Bandit en el pipeline | #2 | **2** hallazgos High / **2** Medium / **1** Low (B324, B201, B608, B104, B105) |
| R1' | Código (SAST) – verificación | Bandit en el pipeline | #4 y #5 | **0** High / **0** Medium / **0** Low (`No issues identified`) |
| R2 | Dependencias (SCA) | pip-audit en el pipeline | #2 | **19** vulnerabilidades en **4** paquetes (Flask, Werkzeug, Jinja2, gunicorn) |
| R2' | Dependencias (SCA) – verificación | pip-audit en el pipeline | #5 | **0** vulnerabilidades (`No known vulnerabilities found`) |
| R3 | Pruebas dinámicas (DAST) | OWASP ZAP sobre staging | #2 | **3** High / **3** Medium / **1** Low |
| R3' | Pruebas dinámicas (DAST) – verificación | OWASP ZAP sobre staging | #4 y #5 | **0** High / **0** Medium / **0** Low |
| R4 | Revisión manual | Lectura de `app.py` | — | 4 vulnerabilidades que las herramientas no reportan directamente: falta de límite de intentos (VULN-06), clave por defecto `admin` (VULN-05), exposición de errores SQL (VULN-02) e inyección en logs (VULN-10) |
| R5 | Producción | Grafana + Prometheus | v1.0.1 y v1.0.5 | Incidente INC-01 detectado por las alertas «Fuerza bruta en login» y «Ataque detectado (XSS/SQLi)» (ver sección 4) |
| R6 | Dependencias (continuo) | Dependabot (GitHub) | PR #1 → build #5 | Dependabot alerts activas; PR agrupado con 6 actualizaciones fusionado y verificado |

## 2. Vulnerabilidades identificadas y corregidas

Todas se corrigieron en el commit `82a8035` (*VULN-01 a VULN-10*), verificado en el **build #4** (Bandit 0/0/0, ZAP 0/0/0, pruebas 9/9)
y desplegado en producción en el **build #5** (versión `1.0.5+f2cb475`).

| ID | Vulnerabilidad (CWE) | Detectada por | Ubicación (código original) | Riesgo | Corrección aplicada | Commit | Build que lo verifica |
|---|---|---|---|---|---|---|---|
| VULN-01 | Inyección SQL (CWE-89) | Bandit B608 (Medium), ZAP *SQL Injection* (High), ataque simulado | `app.py:205` (`/alumnos/buscar`) | Alto | Consulta parametrizada: `WHERE nombre LIKE ?` con el valor como parámetro; el texto del usuario nunca se concatena al SQL | `82a8035` | #4 |
| VULN-02 | Exposición de información en errores (CWE-209) | Revisión manual, ZAP (respuesta 500 con el error) | `app.py:209` | Medio | La respuesta 500 devuelve solo `"Error interno"`; el detalle queda en el log del servidor (`app.logger.exception`) | `82a8035` | #4 |
| VULN-03 | XSS reflejado (CWE-79) | ZAP *Cross Site Scripting (Reflected)* y *(DOM Based)* (High), ataque simulado | `app.py:154` (`/hello`) | Alto | Se escapa la entrada con `markupsafe.escape()` antes de insertarla en el HTML | `82a8035` | #4 |
| VULN-04 | Credenciales y secretos en el código (CWE-798) | Bandit B105 (Low), revisión manual | `app.py:20-23` | Medio | `SECRET_KEY` se lee de una variable de entorno (si no existe, `secrets.token_hex(32)`); usuario y hash del admin se leen de `ADMIN_USUARIO` / `ADMIN_CLAVE_HASH`. Sin hash configurado, el acceso de administrador queda deshabilitado | `82a8035` | #4 |
| VULN-05 | Hash débil MD5 sin sal + clave por defecto `admin` (CWE-327, CWE-521) | Bandit B324 (High), ataque simulado (clave encontrada) | `app.py:22` y `app.py:221` | Alto | `check_password_hash` de Werkzeug (hash con sal) y `hmac.compare_digest` para comparar en tiempo constante | `82a8035` | #4 |
| VULN-06 | Sin límite de intentos de login: fuerza bruta (CWE-307) | Revisión manual, ataque simulado, Grafana | `app.py:214` (`/login`) | Alto | Máximo 5 intentos fallidos por IP en 5 minutos; después responde **HTTP 429** | `82a8035` | #4 (ataque: 26 de 31 intentos bloqueados) |
| VULN-07 | Formulario sin token anti-CSRF (CWE-352) | ZAP *Absence of Anti-CSRF Tokens* (Medium) | `app.py:69` (formulario de login) | Medio | Token aleatorio por sesión (`secrets.token_urlsafe`) en un campo oculto, validado con `hmac.compare_digest`; sin token válido responde 400. Cookie de sesión `HttpOnly` y `SameSite=Lax` | `82a8035` | #4 |
| VULN-08 | Faltan cabeceras de seguridad HTTP (CWE-693, CWE-1021) | ZAP *CSP Header Not Set* (Medium), *Missing Anti-clickjacking Header* (Medium), *X-Content-Type-Options Header Missing* (Low) | `app.py:125` (`after_request`) | Medio | Todas las respuestas incluyen `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy` y `Permissions-Policy` | `82a8035` | #4 |
| VULN-09 | Modo debug activo y escucha en todas las interfaces (CWE-489, CWE-605) | Bandit B201 (High) y B104 (Medium) | `app.py:241` | Alto | `debug=False` y `host="127.0.0.1"`; en los despliegues la app corre con gunicorn | `82a8035` | #4 |
| VULN-10 | Inyección en logs (CWE-117) | Revisión manual | `app.py:225` | Bajo | El usuario se limpia de `\r` y `\n` y se recorta antes de escribirse en el log | `82a8035` | #4 |
| VULN-11 | Componentes con vulnerabilidades conocidas (CWE-1395) | pip-audit (19 CVE), Dependabot alerts | `requirements.txt` | Alto | Actualización con el PR #1 de Dependabot (ver sección 5) | `f2cb475` (PR #1) | #5 |

## 3. Resultados de OWASP ZAP

Escaneo del **build #2** sobre staging (`http://jenkins:5001`), código vulnerable: **3 High, 3 Medium, 1 Low**.
Escaneo de los **builds #4 y #5**, código corregido: **0 High, 0 Medium, 0 Low**.

| Alerta de ZAP | Riesgo | URL de ejemplo | VULN relacionada | Cómo se mitiga | ¿Mitigada? Build |
|---|---|---|---|---|---|
| Cross Site Scripting (DOM Based) | High | `/hello?name=<script>alert(5397)</script>` | VULN-03 | Escapar la salida con `escape()` + cabecera CSP | Sí · #4 |
| Cross Site Scripting (Reflected) | High | `/hello?name=</h1><scrIpt>alert(1);</scRipt><h1>` | VULN-03 | Escapar la salida con `escape()` + cabecera CSP | Sí · #4 |
| SQL Injection | High | `/alumnos/buscar?nombre='` (HTTP 500) | VULN-01, VULN-02 | Consulta parametrizada y mensaje de error genérico | Sí · #4 |
| Absence of Anti-CSRF Tokens | Medium | `/` (formulario `/login`) | VULN-07 | Token anti-CSRF por sesión en el formulario | Sí · #4 |
| Content Security Policy (CSP) Header Not Set | Medium | `/`, `/hello`, `/robots.txt` (5 URL) | VULN-08 | Cabecera `Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'` | Sí · #4 |
| Missing Anti-clickjacking Header | Medium | `/`, `/hello` (3 URL) | VULN-08 | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | Sí · #4 |
| X-Content-Type-Options Header Missing | Low | `/alumnos`, `/alumnos/1` (6 URL) | VULN-08 | `X-Content-Type-Options: nosniff` | Sí · #4 |

Reportes: `zap-report.html`, `zap-alertas.json` y `zap-resumen.txt`, archivados en cada build de Jenkins.

## 4. Monitoreo e incidentes

**Configuración:** Prometheus consulta `/metrics` de producción (`jenkins:5000`) y staging (`jenkins:5001`) cada 5 s.
Grafana usa Prometheus como fuente de datos (`http://prometheus:9090`).

**Dashboard «Producción - Sistema Alumnos»** (actualización cada 5 s):

| Panel | Consulta (PromQL) | Para qué sirve |
|---|---|---|
| Logins fallidos (por minuto) | `increase(login_fallidos_total{job="produccion"}[1m])` | Detectar fuerza bruta |
| Peticiones sospechosas por tipo | `sum by (tipo) (increase(peticiones_sospechosas_total{job="produccion"}[1m]))` | Detectar XSS, SQLi y path traversal |
| Tráfico por ruta y código HTTP | `sum by (endpoint, status) (rate(http_requests_total{job="produccion"}[1m]))` | Ver qué rutas se usan o se atacan |
| Errores 4xx / 5xx | `sum by (status) (rate(http_requests_total{job="produccion",status=~"4..\|5.."}[1m]))` | Ver 401, 429 (bloqueos) y 500 |
| Versión en producción | `app_info{job="produccion"}` | Trazabilidad del despliegue |
| Producción arriba | `up{job="produccion"}` | Disponibilidad |

**Reglas de alerta** (carpeta `EV3`, grupo `seguridad`, evaluación cada 10 s, sin período de espera, *No data = Normal*):

| Regla | Condición | Severidad |
|---|---|---|
| Fuerza bruta en login | `increase(login_fallidos_total{job="produccion"}[1m])` > 10 | Alta |
| Ataque detectado (XSS/SQLi) | `sum(increase(peticiones_sospechosas_total{job="produccion"}[1m]))` > 0 | Alta |

### Incidente INC-01: ataque combinado contra producción (fuerza bruta + inyección SQL + XSS)

| Hora (Chile) | Panel / métrica de Grafana | Qué se observó | Entorno | Clasificación | Acción de respuesta | Verificación |
|---|---|---|---|---|---|---|
| 27-11 ~16:55 | Logins fallidos; Peticiones sospechosas (`sqli`, `xss`); Errores 4xx/5xx (HTTP 401); alertas en **Firing** | ~32 logins fallidos por minuto contra `admin` y picos de peticiones con patrones `sqli` y `xss`. El log muestra «Login fallido…» y «Petición sospechosa…». **El ataque tuvo éxito:** se encontró la clave `admin`, la inyección SQL expuso la estructura de la base de datos y el XSS se reflejó | Producción v`1.0.1+5565711` | **Severidad alta.** Ataque a aplicación web: fuerza bruta (CWE-307), inyección SQL (CWE-89) y XSS (CWE-79) explotados con éxito; compromiso de credenciales y de confidencialidad de datos | **Contención:** el gate del pipeline impide desplegar versiones con hallazgos (builds #2, #3 y #4 bloqueados). **Erradicación:** corrección de VULN-01 a VULN-10 (commit `82a8035`) y actualización de dependencias (PR #1). **Recuperación:** despliegue de v`1.0.5+f2cb475` (build #5). La credencial por defecto se eliminó del código | Ver fila siguiente |
| 27-11 ~17:31 | Mismos paneles; aparece **HTTP 429** y `/login 429` | Se repite el mismo ataque: ~33 intentos por minuto **detectados**, pero **ninguna clave funcionó y 26 de 31 intentos fueron bloqueados (HTTP 429)**; la inyección no devolvió datos y el XSS quedó escapado | Producción v`1.0.5+f2cb475` | Intento de ataque **detectado y bloqueado** (sin impacto) | Ninguna adicional: los controles funcionaron | **Incidente cerrado.** Las mitigaciones quedaron verificadas en producción |

**Lecciones aprendidas:** la monitorización detectó el ataque en segundos, pero la versión vulnerable ya estaba en producción porque el
pipeline original no tenía revisiones de seguridad. Con SAST, SCA, DAST y el gate, una versión así ya no llega a producción.

## 5. Gestión de dependencias

**Proceso:**
1. **Detección continua:** pip-audit corre en cada build (etapa *Dependency Management*) y Dependabot vigila el repositorio (`.github/dependabot.yml`, revisión diaria y alertas activas en *Security → Dependabot alerts*). Commit `aa361c4` (DEPS-01), build #3.
2. **Política:** ninguna versión con CVE conocidos llega a producción, porque pip-audit marca el build como UNSTABLE y el gate bloquea el despliegue (builds #2, #3 y #4).
3. **Actualización:** Dependabot agrupa todas las actualizaciones pip en un solo PR (grupo `dependencias-python`), así Flask y Werkzeug se actualizan juntos y no quedan versiones incompatibles. Se revisó el PR #1 (pestaña *Files changed*) y se fusionó.
4. **Verificación de que no se introducen vulnerabilidades nuevas:** el merge disparó el build #5, donde las 9 pruebas pasaron, pip-audit no encontró vulnerabilidades (0), Bandit y ZAP salieron limpios (0/0/0) y el ataque simulado siguió bloqueado. Solo entonces se desplegó a producción.

| Paquete | Versión inicial | Vulnerabilidades (IDs) | Versión final | Origen del cambio (PR de Dependabot / manual) | ¿Pruebas, pip-audit y ZAP siguen OK? Build |
|---|---|---|---|---|---|
| Flask | 2.2.2 | 2: CVE-2023-30861, CVE-2026-27205 | 3.1.3 | PR #1 de Dependabot | Sí · #5 |
| Werkzeug | 2.2.2 | 10: CVE-2023-25577, CVE-2023-23934, CVE-2023-46136, CVE-2024-34069, CVE-2024-49766, CVE-2024-49767, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2026-102598 | 3.1.9 | PR #1 de Dependabot | Sí · #5 |
| Jinja2 | 3.1.2 | 5: CVE-2024-22195, CVE-2024-34064, CVE-2024-56201, CVE-2024-56326, CVE-2025-27516 | 3.1.6 | PR #1 de Dependabot | Sí · #5 |
| gunicorn | 21.2.0 | 2: CVE-2024-1135, CVE-2024-6827 | 27.0.1 | PR #1 de Dependabot | Sí · #5 |
| prometheus-client | 0.17.1 | 0 | 0.26.0 | PR #1 de Dependabot | Sí · #5 |
| pytest (solo pruebas) | 8.3.4 | 0 | 9.2.0 | PR #1 de Dependabot | Sí · #5 |

**Total:** 19 vulnerabilidades en 4 paquetes (build #2) → **0** (build #5).

## 6. Trazabilidad

Registro generado por Jenkins (`reports/TRAZABILIDAD.md`, build #5):

| Build | Fecha (UTC) | Versión | Commit | Mensaje del commit | Pruebas | Bandit H/M/L | pip-audit | ZAP H/M/L | Resultado | Producción |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | 2026-11-27 19:30 | 1.0.1+5565711 | `5565711` | Codigo base vulnerable | 9/9 OK | n/a | n/a | n/a | SUCCESS | 1.0.1+5565711 |
| 2 | 2026-11-27 19:38 | 1.0.2+837c9be | `837c9be` | PIPE-01: etapas SAST, dependencias, staging, OWASP ZAP y gate de produ | 9/9 OK | 2/2/1 | 19 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 3 | 2026-11-27 20:04 | 1.0.3+aa361c4 | `aa361c4` | DEPS-01: configurar Dependabot para dependencias pip | 9/9 OK | 2/2/1 | 19 vuln. | 3/3/1 | UNSTABLE | no desplegado |
| 4 | 2026-11-27 20:08 | 1.0.4+82a8035 | `82a8035` | VULN-01 a VULN-10: SQLi, errores SQL, XSS, secretos, MD5, fuerza bruta | 9/9 OK | 0/0/0 | 19 vuln. | 0/0/0 | UNSTABLE | no desplegado |
| 5 | 2026-11-27 20:22 | 1.0.5+f2cb475 | `f2cb475` | Merge pull request #1 from pablojimenez23/dependabot/pip/dependencias- | 9/9 OK | 0/0/0 | 0 vuln. | 0/0/0 | SUCCESS | 1.0.5+f2cb475 |

Recorrido de cada actividad del pipeline:

| Actividad | Hallazgo | Build que lo detectó | Commit / PR que lo resolvió | Build que lo verificó | Versión en producción |
|---|---|---|---|---|---|
| Revisión de seguridad (Bandit) | 2 High / 2 Medium / 1 Low: MD5 (B324), debug (B201), SQL (B608), 0.0.0.0 (B104), clave en el código (B105) | #2 | `82a8035` (VULN-01, 04, 05, 09) | #4 (0/0/0) | 1.0.5+f2cb475 |
| Prueba automatizada (OWASP ZAP) | 3 High / 3 Medium / 1 Low: SQLi, XSS reflejado y DOM, CSRF, CSP, clickjacking, nosniff | #2 | `82a8035` (VULN-01, 02, 03, 07, 08) | #4 (0/0/0) | 1.0.5+f2cb475 |
| Gestión de dependencias (pip-audit + Dependabot) | 19 CVE en Flask, Werkzeug, Jinja2 y gunicorn | #2 (y Dependabot alerts) | PR #1 (merge `f2cb475`) | #5 (0 vuln.) | 1.0.5+f2cb475 |
| Monitoreo (Grafana) | INC-01: fuerza bruta + SQLi + XSS exitosos en v1.0.1 | Alertas en Firing, ~16:55 (Chile) | `82a8035` + PR #1 | Ataque repetido a las ~17:31: bloqueado (HTTP 429) | 1.0.5+f2cb475 |

Cada versión desplegada (`1.0.<build>+<commit>`) se ve en `GET /version` y en el panel «Versión en producción» de Grafana, así que
cualquier versión en producción se puede seguir hasta su build, su commit y los reportes de seguridad de ese build.
