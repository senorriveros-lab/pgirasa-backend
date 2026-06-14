"""Backend de licencias/pagos/correo de PGIRASA Tools.

Custodia las llaves sensibles (service_role de Supabase, llaves Wompi y SMTP)
para que NUNCA viajen en la app de escritorio. La app llama a estos endpoints
con una clave compartida (X-App-Key).

Desplegar en Coolify (ver README.md).
"""
import hashlib
import os
import smtplib
import urllib.parse
from datetime import datetime, timedelta, date
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import requests
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

# ── Configuración (variables de entorno en Coolify) ──────────────────────────
APP_API_KEY        = os.getenv("APP_API_KEY", "")
SUPABASE_URL       = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY", "")
WOMPI_PUBLIC_KEY   = os.getenv("WOMPI_PUBLIC_KEY", "")
WOMPI_INTEGRITY_KEY = os.getenv("WOMPI_INTEGRITY_KEY", "")
WOMPI_PRIVATE_KEY  = os.getenv("WOMPI_PRIVATE_KEY", "")
SMTP_REMITENTE     = os.getenv("SMTP_REMITENTE", "")
SMTP_APP_PWD       = os.getenv("SMTP_APP_PWD", "")
SMTP_HOST          = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT          = int(os.getenv("SMTP_PORT", "587"))
PAGO_MONTO         = int(os.getenv("PAGO_MONTO", "15000"))
CODIGO_TTL_MIN     = 15

app = FastAPI(title="PGIRASA Backend", version="1.0.0")


# ── Seguridad: clave compartida ──────────────────────────────────────────────
def _auth(x_app_key: str | None):
    if not APP_API_KEY or x_app_key != APP_API_KEY:
        raise HTTPException(status_code=401, detail="No autorizado.")


# ── Cliente Supabase (service_role) ──────────────────────────────────────────
def _sb_headers(extra=None):
    h = {"apikey": SUPABASE_SERVICE_KEY,
         "Authorization": f"Bearer {SUPABASE_SERVICE_KEY}",
         "Content-Type": "application/json"}
    if extra:
        h.update(extra)
    return h


def _sb(method, path, data=None, headers=None):
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    r = requests.request(method, url, json=data, headers=headers or _sb_headers(), timeout=25)
    r.raise_for_status()
    return r.json() if r.text else None


def _parse_fecha(v):
    if not v:
        return None
    if isinstance(v, date):
        return v
    try:
        return datetime.strptime(str(v)[:10], "%Y-%m-%d").date()
    except Exception:
        return None


# ── Wompi ────────────────────────────────────────────────────────────────────
def _wompi_base():
    return ("https://sandbox.wompi.co/v1" if WOMPI_PUBLIC_KEY.startswith("pub_test_")
            else "https://production.wompi.co/v1")


def _firma(ref, cents, mon="COP"):
    return hashlib.sha256(f"{ref}{cents}{mon}{WOMPI_INTEGRITY_KEY}".encode()).hexdigest()


def _consultar_wompi(referencia="", transaction_id=""):
    base = _wompi_base()
    try:
        if transaction_id:
            r = requests.get(f"{base}/transactions/{urllib.parse.quote(transaction_id)}",
                             headers={"Authorization": f"Bearer {WOMPI_PUBLIC_KEY}"}, timeout=15)
            if r.status_code == 200:
                tx = r.json().get("data") or {}
                return tx if tx.get("status") == "APPROVED" else {}
            return {}
        if referencia and WOMPI_PRIVATE_KEY:
            r = requests.get(f"{base}/transactions",
                             headers={"Authorization": f"Bearer {WOMPI_PRIVATE_KEY}"},
                             params={"reference": referencia}, timeout=15)
            if r.status_code == 200:
                aprob = [t for t in (r.json().get("data") or []) if t.get("status") == "APPROVED"]
                aprob.sort(key=lambda x: x.get("created_at", ""), reverse=True)
                return aprob[0] if aprob else {}
        return {}
    except Exception:
        return {}


# ── SMTP ─────────────────────────────────────────────────────────────────────
def _enviar_correo(destino, asunto, texto, html=""):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = asunto
    msg["From"] = f"Lucreativity <{SMTP_REMITENTE}>"
    msg["To"] = destino
    msg.attach(MIMEText(texto, "plain"))
    if html:
        msg.attach(MIMEText(html, "html"))
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30) as s:
        s.ehlo(); s.starttls(); s.ehlo()
        s.login(SMTP_REMITENTE, SMTP_APP_PWD)
        s.sendmail(SMTP_REMITENTE, destino, msg.as_string())


# ── Códigos OTP (guardados en Supabase, tabla codigos) ───────────────────────
def _guardar_codigo(clave, email, codigo):
    _sb("POST", "codigos?on_conflict=clave", data={
        "clave": clave, "email": email.lower(),
        "hash": hashlib.sha256(codigo.encode()).hexdigest(),
        "exp": (datetime.now() + timedelta(minutes=CODIGO_TTL_MIN)).isoformat(),
    }, headers=_sb_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}))


def _validar_codigo(clave, email, codigo):
    res = _sb("GET", f"codigos?clave=eq.{urllib.parse.quote(clave)}&select=email,hash,exp")
    if not res:
        return "Primero solicita un código."
    d = res[0]
    if _parse_fecha(d["exp"]) and datetime.fromisoformat(d["exp"]) < datetime.now():
        return "El código expiró. Solicita uno nuevo."
    if email.lower() != d.get("email"):
        return "El correo no coincide con el del código."
    if hashlib.sha256(codigo.encode()).hexdigest() != d["hash"]:
        return "El código no es correcto."
    return ""


# ── Modelos ──────────────────────────────────────────────────────────────────
class EnviarCodigo(BaseModel):
    email: str

class Activar(BaseModel):
    serial: str
    device_id: str
    nombre_equipo: str = ""
    codigo: str
    cliente: dict

class Estado(BaseModel):
    serial: str

class Checkout(BaseModel):
    serial: str
    monto: int = 0

class VerificarPago(BaseModel):
    serial: str
    transaction_id: str = ""
    reference: str = ""

class EnviarCorreo(BaseModel):
    destino: str
    asunto: str
    texto: str
    html: str = ""

class Sync(BaseModel):
    tabla: str
    on_conflict: str = ""
    filas: list


# ── Endpoints ────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"ok": True, "service": "pgirasa-backend"}


@app.post("/licencia/enviar-codigo")
def enviar_codigo(body: EnviarCodigo, x_app_key: str = Header(None)):
    _auth(x_app_key)
    email = body.email.strip()
    if "@" not in email:
        raise HTTPException(400, "Correo inválido.")
    codigo = f"{int.from_bytes(os.urandom(3), 'big') % 1000000:06d}"
    _guardar_codigo(f"act:{email.lower()}", email, codigo)
    try:
        _enviar_correo(email, "Código de activación - PGIRASA Tools",
                       f"Tu código de activación es: {codigo}\nVence en {CODIGO_TTL_MIN} minutos.",
                       f"<h2>Activación PGIRASA</h2><p style='font-size:26px;font-weight:bold'>{codigo}</p>")
    except Exception as e:
        raise HTTPException(502, f"No se pudo enviar el correo: {e}")
    return {"ok": True, "mensaje": "Código enviado al correo."}


@app.post("/licencia/estado")
def estado(body: Estado, x_app_key: str = Header(None)):
    _auth(x_app_key)
    res = _sb("GET", f"licencias?serial_compra=eq.{urllib.parse.quote(body.serial)}"
                     f"&select=fecha_vencimiento,tipo_licencia,precio,limite_pcs")
    if not res:
        return {"activa": False, "motivo": "La clave de licencia no existe."}
    lic = res[0]
    venc = _parse_fecha(lic.get("fecha_vencimiento"))
    if not venc:
        return {"activa": False, "motivo": "Licencia sin fecha de vencimiento."}
    dias = (venc - datetime.now().date()).days
    return {"activa": dias >= 0, "dias_restantes": dias,
            "vencimiento": venc.strftime("%Y-%m-%d"),
            "plan": lic.get("tipo_licencia") or "Mensual",
            "precio": int(lic.get("precio") or PAGO_MONTO),
            "motivo": "" if dias >= 0 else "La licencia está vencida."}


@app.post("/licencia/activar")
def activar(body: Activar, x_app_key: str = Header(None)):
    _auth(x_app_key)
    cli = body.cliente or {}
    req_campos = ["razon_social", "nit", "direccion", "ciudad", "telefono", "email"]
    for c in req_campos:
        if not str(cli.get(c, "")).strip():
            raise HTTPException(400, f"Falta el dato obligatorio: {c}")
    err = _validar_codigo(f"act:{cli['email'].strip().lower()}", cli["email"], body.codigo)
    if err:
        return {"ok": False, "mensaje": err}
    res = _sb("GET", f"licencias?serial_compra=eq.{urllib.parse.quote(body.serial)}"
                     f"&select=serial_compra,fecha_vencimiento,limite_pcs")
    if not res:
        return {"ok": False, "mensaje": "La clave de licencia no es válida o no existe."}
    limite = int(res[0].get("limite_pcs") or 2)
    equipos = _sb("GET", f"equipos?serial_ref=eq.{urllib.parse.quote(body.serial)}&select=device_id") or []
    ids = [e.get("device_id") for e in equipos]
    cliente = {c: str(cli.get(c, "")).strip() for c in req_campos}
    cliente["serial_ref"] = body.serial
    _sb("POST", "clientes?on_conflict=serial_ref", data=cliente,
        headers=_sb_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}))
    if body.device_id in ids:
        return {"ok": True, "mensaje": "Este equipo ya estaba registrado. Licencia activada."}
    if len(ids) >= limite:
        return {"ok": False, "mensaje": f"Esta licencia ya está en uso en {limite} equipos."}
    _sb("POST", "equipos", data={"serial_ref": body.serial, "device_id": body.device_id,
                                 "nombre_equipo": body.nombre_equipo,
                                 "registrado_en": datetime.now().isoformat()},
        headers=_sb_headers({"Prefer": "return=minimal"}))
    return {"ok": True, "mensaje": f"¡Licencia activada! Equipos en uso: {len(ids)+1} de {limite}."}


@app.post("/pago/checkout")
def checkout(body: Checkout, x_app_key: str = Header(None)):
    _auth(x_app_key)
    monto = body.monto if body.monto > 0 else PAGO_MONTO
    cents = monto * 100
    ref = f"PGIRASA-{body.serial}-{int(datetime.now().timestamp())}"
    params = {"public-key": WOMPI_PUBLIC_KEY, "currency": "COP",
              "amount-in-cents": str(cents), "reference": ref,
              "signature:integrity": _firma(ref, cents)}
    url = "https://checkout.wompi.co/p/?" + urllib.parse.urlencode(params)
    return {"url": url, "reference": ref}


@app.post("/pago/verificar")
def verificar(body: VerificarPago, x_app_key: str = Header(None)):
    _auth(x_app_key)
    tx = _consultar_wompi(transaction_id=body.transaction_id, referencia=body.reference)
    if not tx:
        return {"ok": False, "mensaje": "Aún no aparece un pago APROBADO en Wompi."}
    id_op = str(tx.get("id", ""))
    # Idempotencia: no aplicar dos veces el mismo pago
    if id_op and _sb("GET", f"pagos?id_operacion=eq.{urllib.parse.quote(id_op)}&select=id_operacion"):
        return {"ok": False, "mensaje": "Este pago ya había sido aplicado."}
    cust = tx.get("customer_data") or {}
    _sb("POST", "pagos?on_conflict=id_operacion", data={
        "id_operacion": id_op, "estado": "Aprobado",
        "monto": (tx.get("amount_in_cents", 0) or 0) / 100.0,
        "email_pagador": cust.get("email") or "", "serial_ref": body.serial,
        "fecha": tx.get("finalized_at") or tx.get("created_at") or datetime.now().isoformat(),
    }, headers=_sb_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}))
    # Extender 30 días
    res = _sb("GET", f"licencias?serial_compra=eq.{urllib.parse.quote(body.serial)}&select=fecha_vencimiento")
    base = datetime.now().date()
    if res:
        v = _parse_fecha(res[0].get("fecha_vencimiento"))
        if v:
            base = max(base, v)
    nueva = (base + timedelta(days=30)).strftime("%Y-%m-%d")
    _sb("PATCH", f"licencias?serial_compra=eq.{urllib.parse.quote(body.serial)}",
        data={"fecha_vencimiento": nueva}, headers=_sb_headers({"Prefer": "return=minimal"}))
    return {"ok": True, "vencimiento": nueva, "mensaje": f"✓ Pago aprobado. Vence el {nueva}."}


@app.post("/email/enviar")
def email_enviar(body: EnviarCorreo, x_app_key: str = Header(None)):
    _auth(x_app_key)
    try:
        _enviar_correo(body.destino, body.asunto, body.texto, body.html)
    except Exception as e:
        raise HTTPException(502, f"No se pudo enviar el correo: {e}")
    return {"ok": True}


@app.post("/datos/sync")
def datos_sync(body: Sync, x_app_key: str = Header(None)):
    _auth(x_app_key)
    if not body.filas:
        return {"ok": True, "filas": 0}
    path = f"{body.tabla}?on_conflict={body.on_conflict}" if body.on_conflict else body.tabla
    try:
        _sb("POST", path, data=body.filas,
            headers=_sb_headers({"Prefer": "resolution=merge-duplicates,return=minimal"}))
    except requests.HTTPError as e:
        raise HTTPException(502, f"Error al sincronizar {body.tabla}: {e}")
    return {"ok": True, "filas": len(body.filas)}
