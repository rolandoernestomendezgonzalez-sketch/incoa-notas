from flask import Flask, request, jsonify
from flask_cors import CORS
from models import db, Usuario, Materia, Nota, Periodo
from werkzeug.security import check_password_hash, generate_password_hash
import secrets
import os

app = Flask(__name__)

# ── Base de datos (PostgreSQL en producción via variable de entorno) ──
db_url = os.environ.get("DATABASE_URL", "")

# Neon/Heroku a veces entregan "postgres://" pero SQLAlchemy necesita "postgresql://"
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

if not db_url:
    raise RuntimeError(
        "La variable de entorno DATABASE_URL no está definida. "
        "Agrégala en Vercel → Settings → Environment Variables."
    )

app.config["SQLALCHEMY_DATABASE_URI"] = db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# SSL requerido por Neon (ya viene en la URL con ?sslmode=require, pero esto lo refuerza)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "connect_args": {"sslmode": "require"},
}

CORS(app, origins="*", allow_headers=["Content-Type", "X-Token"])
db.init_app(app)

# ── Límites del sistema ───────────────────────────────────────────────
MAX_ESTUDIANTES = 15
MAX_TOTAL       = 25   # estudiantes + maestros + admins

# ── Token store simple en memoria ────────────────────────────────────
# Nota: en serverless cada instancia tiene su propia memoria.
# Para producción seria, reemplazar con Redis o JWT.
_tokens: dict[str, int] = {}

def generar_token(usuario_id: int) -> str:
    tok = secrets.token_hex(32)
    _tokens[tok] = usuario_id
    return tok

def usuario_actual():
    tok = request.headers.get("X-Token", "")
    uid = _tokens.get(tok)
    if not uid:
        return None
    return db.session.get(Usuario, uid)

# ── AUTH ──────────────────────────────────────────────────────────────

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    usuario = Usuario.query.filter_by(codigo=data.get("codigo")).first()
    if not usuario or not check_password_hash(usuario.password_hash, data.get("password", "")):
        return jsonify({"error": "Credenciales incorrectas"}), 401
    if not usuario.activo:
        return jsonify({"error": "Usuario inactivo. Contacta al administrador."}), 403
    token = generar_token(usuario.id)
    return jsonify({
        "ok": True, "token": token,
        "rol": usuario.rol, "nombre": usuario.nombre,
        "codigo": usuario.codigo, "id": usuario.id
    })

@app.route("/api/logout", methods=["POST"])
def logout():
    tok = request.headers.get("X-Token", "")
    _tokens.pop(tok, None)
    return jsonify({"ok": True})

@app.route("/api/me", methods=["GET"])
def me():
    u = usuario_actual()
    if not u:
        return jsonify({"error": "No autenticado"}), 401
    return jsonify({"id": u.id, "nombre": u.nombre, "rol": u.rol, "codigo": u.codigo})

# ── ESTUDIANTES ───────────────────────────────────────────────────────

@app.route("/api/estudiantes", methods=["GET"])
def get_estudiantes():
    estudiantes = Usuario.query.filter_by(rol="estudiante").all()
    return jsonify([{
        "id": e.id, "nombre": e.nombre, "codigo": e.codigo, "activo": e.activo
    } for e in estudiantes])

@app.route("/api/estudiantes/<int:eid>/notas", methods=["GET"])
def get_notas_estudiante(eid):
    periodo_id = request.args.get("periodo_id")
    q = Nota.query.filter_by(estudiante_id=eid)
    if periodo_id:
        q = q.filter_by(periodo_id=periodo_id)
    notas = q.all()
    resultado = []
    for n in notas:
        m = db.session.get(Materia, n.materia_id)
        p = db.session.get(Periodo, n.periodo_id)
        resultado.append({
            "id": n.id,
            "materia": m.nombre if m else "—",
            "nota": n.valor,
            "periodo": p.nombre if p else "—",
            "periodo_id": n.periodo_id
        })
    return jsonify(resultado)

# ── MAESTROS ──────────────────────────────────────────────────────────

@app.route("/api/maestros", methods=["GET"])
def get_maestros():
    maestros = Usuario.query.filter(Usuario.rol.in_(["maestro", "admin"])).all()
    return jsonify([{"id": m.id, "nombre": m.nombre, "codigo": m.codigo, "rol": m.rol} for m in maestros])

@app.route("/api/maestros/<int:mid>/materias", methods=["GET"])
def get_materias_maestro(mid):
    materias = Materia.query.filter_by(maestro_id=mid).all()
    return jsonify([{"id": m.id, "nombre": m.nombre} for m in materias])

# ── NOTAS ─────────────────────────────────────────────────────────────

@app.route("/api/notas", methods=["GET"])
def get_notas():
    materia_id = request.args.get("materia_id")
    periodo_id = request.args.get("periodo_id")
    q = Nota.query
    if materia_id:
        q = q.filter_by(materia_id=materia_id)
    if periodo_id:
        q = q.filter_by(periodo_id=periodo_id)
    notas = q.all()
    resultado = []
    for n in notas:
        e = db.session.get(Usuario, n.estudiante_id)
        m = db.session.get(Materia, n.materia_id)
        p = db.session.get(Periodo, n.periodo_id)
        resultado.append({
            "id": n.id,
            "estudiante": e.nombre if e else "—",
            "estudiante_id": n.estudiante_id,
            "materia": m.nombre if m else "—",
            "periodo": p.nombre if p else "—",
            "nota": n.valor
        })
    return jsonify(resultado)

@app.route("/api/notas", methods=["POST"])
def guardar_nota():
    data = request.get_json()
    nota = Nota.query.filter_by(
        estudiante_id=data["estudiante_id"],
        materia_id=data["materia_id"],
        periodo_id=data["periodo_id"]
    ).first()
    if nota:
        nota.valor = data["valor"]
    else:
        nota = Nota(
            estudiante_id=data["estudiante_id"],
            materia_id=data["materia_id"],
            periodo_id=data["periodo_id"],
            valor=data["valor"]
        )
        db.session.add(nota)
    db.session.commit()
    return jsonify({"ok": True, "id": nota.id})

@app.route("/api/notas/<int:nid>", methods=["DELETE"])
def eliminar_nota(nid):
    n = db.session.get(Nota, nid)
    if not n:
        return jsonify({"error": "Nota no encontrada"}), 404
    db.session.delete(n)
    db.session.commit()
    return jsonify({"ok": True})

# ── MATERIAS ──────────────────────────────────────────────────────────

@app.route("/api/materias", methods=["GET"])
def get_materias():
    materias = Materia.query.all()
    return jsonify([{
        "id": m.id, "nombre": m.nombre,
        "maestro_id": m.maestro_id,
        "maestro": db.session.get(Usuario, m.maestro_id).nombre if m.maestro_id else "—"
    } for m in materias])

@app.route("/api/materias", methods=["POST"])
def crear_materia():
    data = request.get_json()
    m = Materia(nombre=data["nombre"], maestro_id=data.get("maestro_id"))
    db.session.add(m)
    db.session.commit()
    return jsonify({"ok": True, "id": m.id})

@app.route("/api/materias/<int:mid>", methods=["DELETE"])
def eliminar_materia(mid):
    m = db.session.get(Materia, mid)
    if not m:
        return jsonify({"error": "Materia no encontrada"}), 404
    Nota.query.filter_by(materia_id=mid).delete()
    db.session.delete(m)
    db.session.commit()
    return jsonify({"ok": True})

# ── PERIODOS ──────────────────────────────────────────────────────────

@app.route("/api/periodos", methods=["GET"])
def get_periodos():
    periodos = Periodo.query.all()
    return jsonify([{"id": p.id, "nombre": p.nombre, "activo": p.activo} for p in periodos])

@app.route("/api/periodos/<int:pid>/toggle", methods=["POST"])
def toggle_periodo(pid):
    p = db.session.get(Periodo, pid)
    if not p:
        return jsonify({"error": "Periodo no encontrado"}), 404
    p.activo = not p.activo
    db.session.commit()
    return jsonify({"ok": True, "activo": p.activo})

@app.route("/api/periodos", methods=["POST"])
def crear_periodo():
    data = request.get_json()
    p = Periodo(nombre=data["nombre"], activo=data.get("activo", False))
    db.session.add(p)
    db.session.commit()
    return jsonify({"ok": True, "id": p.id})

# ── ADMIN: gestión de usuarios ────────────────────────────────────────

@app.route("/api/usuarios", methods=["GET"])
def get_usuarios():
    usuarios = Usuario.query.all()
    return jsonify([{
        "id": u.id, "nombre": u.nombre, "codigo": u.codigo, "rol": u.rol, "activo": u.activo
    } for u in usuarios])

@app.route("/api/usuarios", methods=["POST"])
def crear_usuario():
    data = request.get_json()

    if Usuario.query.filter_by(codigo=data["codigo"]).first():
        return jsonify({"error": "Ese código ya existe en el sistema"}), 400

    total = Usuario.query.count()
    if total >= MAX_TOTAL:
        return jsonify({"error": f"Límite de {MAX_TOTAL} usuarios alcanzado"}), 400

    if data["rol"] == "estudiante":
        total_est = Usuario.query.filter_by(rol="estudiante").count()
        if total_est >= MAX_ESTUDIANTES:
            return jsonify({"error": f"Límite de {MAX_ESTUDIANTES} estudiantes alcanzado"}), 400

    u = Usuario(
        nombre=data["nombre"],
        codigo=data["codigo"],
        rol=data["rol"],
        password_hash=generate_password_hash(data["password"]),
        activo=True
    )
    db.session.add(u)
    db.session.commit()
    return jsonify({"ok": True, "id": u.id})

@app.route("/api/usuarios/<int:uid>", methods=["PATCH"])
def editar_usuario(uid):
    u = db.session.get(Usuario, uid)
    if not u:
        return jsonify({"error": "Usuario no encontrado"}), 404
    data = request.get_json()
    if "nombre" in data:
        u.nombre = data["nombre"]
    if "activo" in data:
        u.activo = data["activo"]
    if "password" in data and data["password"]:
        u.password_hash = generate_password_hash(data["password"])
    db.session.commit()
    return jsonify({"ok": True})

@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def eliminar_usuario(uid):
    u = db.session.get(Usuario, uid)
    if not u:
        return jsonify({"error": "Usuario no encontrado"}), 404
    Nota.query.filter_by(estudiante_id=uid).delete()
    db.session.delete(u)
    db.session.commit()
    return jsonify({"ok": True})

# ── RESUMEN ADMIN ─────────────────────────────────────────────────────

@app.route("/api/resumen", methods=["GET"])
def resumen():
    total_est = Usuario.query.filter_by(rol="estudiante").count()
    total_mae = Usuario.query.filter_by(rol="maestro").count()
    total_adm = Usuario.query.filter_by(rol="admin").count()
    total_notas = Nota.query.count()
    periodo_activo = Periodo.query.filter_by(activo=True).first()

    materias = Materia.query.all()
    avance = []
    for m in materias:
        ingresadas = Nota.query.filter_by(materia_id=m.id).count()
        maestro = db.session.get(Usuario, m.maestro_id)
        avance.append({
            "materia": m.nombre,
            "maestro": maestro.nombre if maestro else "—",
            "ingresadas": ingresadas,
            "esperadas": total_est
        })

    return jsonify({
        "total_estudiantes": total_est,
        "total_maestros": total_mae,
        "total_admins": total_adm,
        "total_usuarios": total_est + total_mae + total_adm,
        "max_estudiantes": MAX_ESTUDIANTES,
        "max_total": MAX_TOTAL,
        "total_notas": total_notas,
        "periodo_activo": periodo_activo.nombre if periodo_activo else None,
        "periodo_activo_id": periodo_activo.id if periodo_activo else None,
        "avance_materias": avance
    })

# ── INIT ──────────────────────────────────────────────────────────────

def inicializar_db():
    """Crea las tablas y el admin inicial si no existe."""
    db.create_all()
    if not Usuario.query.filter_by(codigo="ADMIN-001").first():
        admin = Usuario(
            nombre="Administrador Principal",
            codigo="ADMIN-001",
            rol="admin",
            password_hash=generate_password_hash("admin123"),
            activo=True
        )
        db.session.add(admin)
        db.session.commit()
        print("✅  BD creada. Admin inicial: ADMIN-001 / admin123")

# Se ejecuta tanto con Vercel (gunicorn) como con python app.py directamente
with app.app_context():
    inicializar_db()

if __name__ == "__main__":
    app.run(debug=True, port=5000)
