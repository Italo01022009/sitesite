-- ============================================================
--  SCHEMA — MeuApp (Supabase / PostgreSQL)
--  Execute no SQL Editor do painel Supabase
-- ============================================================

-- ── 1. Tabela de perfis ──────────────────────────────────────
-- Armazena dados extras do usuário além do que o Supabase Auth guarda.
-- A coluna "id" referencia diretamente auth.users, garantindo integridade.

create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  full_name   text,
  email       text unique,
  avatar_url  text,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now()
);

-- ── 2. Trigger: cria perfil automaticamente ao registrar ────
-- Quando o usuário faz login pela 1ª vez via OAuth, o Supabase Auth
-- insere uma linha em auth.users. Este trigger replica os dados
-- básicos na tabela profiles sem nenhuma chamada manual.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer          -- roda com permissão de serviço
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, email, avatar_url)
  values (
    new.id,
    new.raw_user_meta_data ->> 'full_name',   -- vindo do Google
    new.email,
    new.raw_user_meta_data ->> 'avatar_url'
  )
  on conflict (id) do update              -- se já existir, atualiza
    set full_name  = excluded.full_name,
        email      = excluded.email,
        avatar_url = excluded.avatar_url,
        updated_at = now();
  return new;
end;
$$;

-- Remove trigger antigo se existir, depois recria
drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ── 3. Trigger: atualiza "updated_at" automaticamente ───────

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists set_profiles_updated_at on public.profiles;

create trigger set_profiles_updated_at
  before update on public.profiles
  for each row execute procedure public.set_updated_at();

-- ── 4. Row Level Security (RLS) ─────────────────────────────
-- Garante que cada usuário só acessa/edita o próprio perfil.

alter table public.profiles enable row level security;

-- Qualquer usuário autenticado pode ler seu próprio perfil
create policy "Usuário lê o próprio perfil"
  on public.profiles for select
  using ( auth.uid() = id );

-- Usuário só atualiza o próprio perfil
create policy "Usuário atualiza o próprio perfil"
  on public.profiles for update
  using ( auth.uid() = id );

-- O trigger (security definer) pode inserir ao criar conta
create policy "Service role pode inserir perfil"
  on public.profiles for insert
  with check ( true );

-- ── 5. (Opcional) Tabela de sessões/logs de acesso ──────────
-- Útil para auditoria ou para mostrar "último acesso".

create table if not exists public.access_logs (
  id          bigserial primary key,
  user_id     uuid references auth.users(id) on delete cascade,
  logged_at   timestamptz not null default now(),
  ip_address  text,
  user_agent  text
);

alter table public.access_logs enable row level security;

create policy "Usuário vê os próprios logs"
  on public.access_logs for select
  using ( auth.uid() = user_id );

-- ── 6. Índices ───────────────────────────────────────────────
create index if not exists profiles_email_idx    on public.profiles (email);
create index if not exists access_logs_user_idx  on public.access_logs (user_id);

-- ============================================================
--  PRONTO! Após rodar este script:
--  1. Vá em Authentication → Providers → Google no Supabase
--  2. Cole o Client ID e Client Secret do Google Cloud Console
--  3. No Google Cloud Console, adicione como URI autorizado:
--     https://SEU_PROJECT_ID.supabase.co/auth/v1/callback
-- ============================================================
