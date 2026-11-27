"""!
@file app.py
@brief "Sistema Alumnos" de SecureDev: API y portal web de alumnos (Evaluación Parcial 3, OCY1102).

Además de las rutas de negocio, la app publica métricas para Prometheus en /metrics.
Las métricas de seguridad (logins fallidos y peticiones sospechosas) se ven en Grafana.

Correcciones de seguridad aplicadas (ver docs/REGISTRO_SEGURIDAD.md):
  VULN-01 Inyección SQL en /alumnos/buscar            -> consulta parametrizada
  VULN-02 Exposición de errores SQL al cliente         -> mensaje genérico, detalle solo en el log
  VULN-03 XSS reflejado en /hello                      -> escape de la entrada del usuario
  VULN-04 Secretos escritos en el código               -> variables de entorno / clave aleatoria
  VULN-05 Clave del admin en MD5 sin sal               -> hash fuerte (werkzeug) + comparación segura
  VULN-06 Login sin límite de intentos (fuerza bruta)  -> bloqueo por IP con HTTP 429
  VULN-07 Formulario de login sin token anti-CSRF      -> token CSRF por sesión
  VULN-08 Faltan cabeceras de seguridad HTTP           -> CSP, X-Frame-Options, nosniff, etc.
  VULN-09 Modo debug activo y escucha en 0.0.0.0       -> debug desactivado, solo localhost
  VULN-10 Inyección en logs (log injection)            -> se limpian saltos de línea
"""
import hmac
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque
from threading import Lock

from flask import Flask, Response, g, jsonify, render_template_string, request, session
from markupsafe import escape
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from werkzeug.security import check_password_hash

app = Flask(__name__)

## VULN-04: la clave de la app se lee del entorno; si no existe, se genera una aleatoria al iniciar.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
## Cookie de sesión protegida (no accesible desde JavaScript y no enviada en peticiones de otros sitios).
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

## VULN-04 / VULN-05: credenciales del administrador fuera del código.
## ADMIN_CLAVE_HASH se genera con werkzeug.security.generate_password_hash(). Si no está definida,
## el acceso de administrador queda deshabilitado (falla de forma segura).
ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
ADMIN_CLAVE_HASH = os.environ.get("ADMIN_CLAVE_HASH", "")

## VULN-06: máximo de intentos fallidos por IP dentro de la ventana de tiempo.
MAX_INTENTOS = 5
VENTANA_SEGUNDOS = 300
INTENTOS_FALLIDOS = defaultdict(deque)
CANDADO_INTENTOS = Lock()

## Versión desplegada: la inyecta el pipeline (1.0.<build>+<commit>). Sirve para la trazabilidad.
VERSION = os.environ.get("APP_VERSION", "dev")
## Archivo SQLite con los alumnos (cada entorno usa el suyo).
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")

ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]

# ---------------------------------------------------------------- métricas (no modificar los nombres)
HTTP_PETICIONES = Counter("http_requests_total", "Peticiones HTTP atendidas", ["method", "endpoint", "status"])
HTTP_LATENCIA = Histogram("http_request_duration_seconds", "Duración de las peticiones HTTP", ["endpoint"])
LOGIN_FALLIDOS = Counter("login_fallidos_total", "Intentos de inicio de sesión fallidos")
LOGIN_EXITOSOS = Counter("login_exitosos_total", "Inicios de sesión correctos")
SOSPECHOSAS = Counter("peticiones_sospechosas_total", "Peticiones con patrones de ataque", ["tipo"])
APP_INFO = Gauge("app_info", "Versión desplegada de la aplicación", ["version"])
APP_INFO.labels(version=VERSION).set(1)

## Patrones que delatan un intento de ataque (detección, no bloqueo).
PATRONES_ATAQUE = {
    "xss": re.compile(r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img", re.I),
    "sqli": re.compile(r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(", re.I),
    "path_traversal": re.compile(r"\.\./|\.\.\\|%2e%2e", re.I),
}

## VULN-08: cabeceras de seguridad que se agregan a todas las respuestas.
CABECERAS_SEGURIDAD = {
    "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}

PORTADA = """<!doctype html>
<html lang="es">
<head><meta charset="utf-8"><title>Sistema Alumnos</title></head>
<body>
<h1>Sistema Alumnos · SecureDev</h1>
<p>Versión {{ version }}</p>
<ul>
  <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
  <li><a href="/alumnos/1">Alumno 1</a></li>
  <li><a href="/hello?name=Ana">Saludo</a></li>
</ul>
<h2>Buscar alumno</h2>
<form action="/alumnos/buscar" method="get">
  <input name="nombre" value="Ana"> <button type="submit">Buscar</button>
</form>
<h2>Acceso administrador</h2>
<form action="/login" method="post">
  <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
  <input name="usuario" value="admin"> <input name="clave" type="password" value="">
  <button type="submit">Entrar</button>
</form>
</body>
</html>"""


def obtener_token_csrf():
    """!
    @brief VULN-07: devuelve el token anti-CSRF de la sesión (lo crea si no existe).
    @return Token aleatorio ligado a la sesión del usuario.
    """
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = obtener_token_csrf


def limpiar_para_log(texto):
    """!
    @brief VULN-10: quita saltos de línea y recorta el texto antes de escribirlo en el log.
    @param texto Valor enviado por el usuario.
    @return Texto seguro para una sola línea de log.
    """
    return texto.replace("\r", " ").replace("\n", " ")[:50]


def ip_bloqueada(ip):
    """!
    @brief VULN-06: indica si la IP superó el máximo de intentos fallidos en la ventana de tiempo.
    @param ip Dirección IP del cliente.
    @return True si la IP debe ser bloqueada.
    """
    ahora = time.time()
    with CANDADO_INTENTOS:
        intentos = INTENTOS_FALLIDOS[ip]
        while intentos and ahora - intentos[0] > VENTANA_SEGUNDOS:
            intentos.popleft()
        return len(intentos) >= MAX_INTENTOS


def registrar_intento_fallido(ip):
    """!
    @brief VULN-06: guarda la hora de un intento fallido para la IP.
    @param ip Dirección IP del cliente.
    """
    with CANDADO_INTENTOS:
        INTENTOS_FALLIDOS[ip].append(time.time())


def conectar():
    """!
    @brief Abre (una vez por petición) la conexión a la base de datos SQLite.
    @return Conexión sqlite3 con filas accesibles por nombre de columna.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    """!
    @brief Cierra la conexión a la base de datos al terminar cada petición.
    @param _error Excepción de la petición (si la hubo); no se usa.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    """!
    @brief Crea la tabla de alumnos y carga los datos iniciales si está vacía.
    """
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS alumnos (id INTEGER PRIMARY KEY, nombre TEXT, carrera TEXT, promedio REAL)")
    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany("INSERT INTO alumnos VALUES (?, ?, ?, ?)", ALUMNOS_INICIALES)
    db.commit()
    db.close()


@app.before_request
def antes_de_la_peticion():
    """!
    @brief Marca el inicio de la petición y cuenta los parámetros con patrones de ataque.
    """
    g.inicio = time.perf_counter()
    valores = list(request.args.values()) + list(request.form.values())
    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(v) for v in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()
            app.logger.warning("Petición sospechosa (%s) desde %s a %s", tipo, request.remote_addr, request.path)


@app.after_request
def despues_de_la_peticion(respuesta):
    """!
    @brief Registra la métrica de cada petición y agrega las cabeceras de seguridad (VULN-08).
    @param respuesta Respuesta que Flask enviará al cliente.
    @return La misma respuesta.
    """
    for cabecera, valor in CABECERAS_SEGURIDAD.items():
        respuesta.headers.setdefault(cabecera, valor)
    endpoint = request.url_rule.rule if request.url_rule else "desconocido"
    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(request.method, endpoint, str(respuesta.status_code)).inc()
        HTTP_LATENCIA.labels(endpoint).observe(time.perf_counter() - g.get("inicio", time.perf_counter()))
    return respuesta


@app.route("/")
def portada():
    """!
    @brief Portada HTML con enlaces y formularios del sistema.
    @return Página HTML.
    """
    return render_template_string(PORTADA, version=VERSION)


@app.route("/hello")
def hello():
    """!
    @brief Saluda al usuario cuyo nombre llega en el parámetro de URL «name».
    @return Página HTML con el saludo.
    """
    name = request.args.get("name", "visitante")
    # VULN-03: se escapa la entrada (< > & " ') para que el navegador la muestre como texto, no como código
    return f"<h1>Hola, {escape(name)}!</h1>"


@app.route("/health")
def health():
    """!
    @brief Estado de la aplicación (lo usan el despliegue y el monitoreo).
    @return JSON {"estado": "ok"}.
    """
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    """!
    @brief Versión desplegada, para la trazabilidad.
    @return JSON con el nombre y la versión de la aplicación.
    """
    return jsonify({"aplicacion": "Sistema Alumnos", "version": VERSION})


@app.route("/alumnos")
def listar_alumnos():
    """!
    @brief Lista todos los alumnos.
    @return JSON con la lista de alumnos.
    """
    filas = conectar().execute("SELECT * FROM alumnos ORDER BY id").fetchall()
    return jsonify([dict(f) for f in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    """!
    @brief Obtiene un alumno por su identificador.
    @param alumno_id Identificador numérico del alumno.
    @return JSON con el alumno, o error 404 si no existe.
    """
    fila = conectar().execute("SELECT * FROM alumnos WHERE id = ?", (alumno_id,)).fetchone()
    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404
    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    """!
    @brief Busca alumnos cuyo nombre contenga el texto del parámetro «nombre».
    @return JSON con los alumnos encontrados.
    """
    nombre = request.args.get("nombre", "")
    try:
        # VULN-01: consulta parametrizada; el texto del usuario nunca se concatena al SQL
        filas = conectar().execute(
            "SELECT * FROM alumnos WHERE nombre LIKE ?", (f"%{nombre}%",)
        ).fetchall()
    except sqlite3.Error:
        # VULN-02: no se exponen el error ni la consulta al cliente; el detalle queda solo en el log
        app.logger.exception("Error en la búsqueda de alumnos")
        return jsonify({"error": "Error interno"}), 500
    return jsonify([dict(f) for f in filas])


@app.route("/login", methods=["POST"])
def login():
    """!
    @brief Valida las credenciales del administrador enviadas por formulario.
    @return JSON con el resultado; 400 sin token CSRF, 429 si la IP está bloqueada, 401 si no son válidas.
    """
    ip = request.remote_addr or "desconocida"

    # VULN-06: bloqueo temporal por exceso de intentos fallidos
    if ip_bloqueada(ip):
        LOGIN_FALLIDOS.inc()
        app.logger.warning("Login bloqueado por exceso de intentos desde %s", ip)
        return jsonify({"error": "Demasiados intentos. Espera unos minutos."}), 429

    # VULN-07: el formulario debe traer el token anti-CSRF de la sesión
    token = request.form.get("csrf_token", "")
    if not token or not hmac.compare_digest(token, session.get("csrf_token", "")):
        app.logger.warning("Login rechazado: token CSRF inválido desde %s", ip)
        return jsonify({"error": "Solicitud inválida"}), 400

    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")
    # VULN-05: comparación en tiempo constante y hash fuerte con sal (no MD5)
    usuario_ok = hmac.compare_digest(usuario.encode(), ADMIN_USUARIO.encode())
    clave_ok = bool(ADMIN_CLAVE_HASH) and check_password_hash(ADMIN_CLAVE_HASH, clave)
    if usuario_ok and clave_ok:
        LOGIN_EXITOSOS.inc()
        return jsonify({"mensaje": "Bienvenido, administrador"})

    registrar_intento_fallido(ip)
    LOGIN_FALLIDOS.inc()
    # VULN-10: el usuario se limpia antes de escribirlo en el log
    app.logger.warning("Login fallido para el usuario %r desde %s", limpiar_para_log(usuario), ip)
    return jsonify({"error": "Credenciales inválidas"}), 401


@app.route("/metrics")
def metrics():
    """!
    @brief Métricas en formato Prometheus.
    @return Texto con las métricas.
    """
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)


iniciar_db()

if __name__ == "__main__":
    # VULN-09: sin modo debug (el depurador de Werkzeug permite ejecutar código) y solo en localhost.
    # En los despliegues la app corre con gunicorn (scripts/deploy.sh), no con este bloque.
    app.run(host="127.0.0.1", port=5000, debug=False)