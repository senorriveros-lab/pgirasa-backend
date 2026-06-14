# Backend de PGIRASA Tools

Servicio que custodia las llaves sensibles (service_role de Supabase, llaves
Wompi y SMTP). La app de escritorio NO lleva esas llaves: solo conoce la URL
del backend y la clave compartida `APP_API_KEY`.

## 1. Crear la tabla de códigos en Supabase
En Supabase Studio → SQL Editor, ejecuta `supabase_backend.sql`.

## 2. Desplegar en Coolify
1. Sube esta carpeta `backend/` a un repositorio Git (GitHub, etc.).
2. En Coolify → **+ New → Application → Public/Private Repository**.
3. Build Pack: **Dockerfile** (Coolify detecta el `Dockerfile`).
4. Puerto expuesto: **8080**.
5. En **Environment Variables**, carga todas las del archivo `.env.example`
   con sus valores reales (especialmente `APP_API_KEY`, `SUPABASE_SERVICE_KEY`,
   las de Wompi y SMTP).
6. Asigna un dominio, por ejemplo `https://api.lucreativity.site`, y **Deploy**.
7. Verifica: abre `https://api.lucreativity.site/health` → debe responder
   `{"ok": true, ...}`.

## 3. Configurar la app de escritorio
En el `.env` de la app deja SOLO:
```
BACKEND_URL=https://api.lucreativity.site
APP_API_KEY=la-misma-clave-larga-del-backend
SUPABASE_URL=http://supabase.lucreativity.site
SUPABASE_KEY=eyJ... (anon, pública)
GROQ_API_KEY=...
```
Y **elimina** del `.env` de la app: `SUPABASE_SERVICE_KEY`, `WOMPI_*` y
`SMTP_*`. Esas viven solo en el backend.

## Generar APP_API_KEY
```
python -c "import secrets; print(secrets.token_hex(32))"
```
Usa el mismo valor en el backend (Coolify) y en la app.
