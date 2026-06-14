-- Tabla para los códigos de verificación (OTP) que usa el backend.
-- Ejecutar en Supabase Studio → SQL Editor → Run.
create table if not exists public.codigos (
    clave     text primary key,   -- ej: 'act:correo@dominio.com'
    email     text,
    hash      text,
    exp       timestamptz,
    creado_en timestamptz default now()
);
alter table public.codigos enable row level security;
-- Sin políticas para anon: solo el backend (service_role) la usa.
