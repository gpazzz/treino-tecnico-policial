-- Treino Técnico-Policial v1.2 — acesso por número mecanográfico + PIN
-- Execute este ficheiro UMA VEZ no SQL Editor do Supabase.
-- Não volte a executar os ficheiros das 368 perguntas.
-- Administrador inicial: 202688
-- Código de ativação inicial (uso único): 08827412

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.app_users (
  mechanical_no text primary key check (mechanical_no ~ '^[0-9]{6}$'),
  display_name text,
  active boolean not null default true,
  is_admin boolean not null default false,
  activation_hash text,
  pin_hash text,
  activated_at timestamptz,
  failed_attempts integer not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now(),
  last_login_at timestamptz
);

create table if not exists public.app_sessions (
  id uuid primary key default gen_random_uuid(),
  token_hash bytea unique not null,
  mechanical_no text not null references public.app_users(mechanical_no) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default (now() + interval '30 days')
);

create table if not exists public.training_stats (
  mechanical_no text primary key references public.app_users(mechanical_no) on delete cascade,
  stats jsonb not null default '{"byQuestion":{},"history":[],"bookmarks":[]}'::jsonb,
  updated_at timestamptz not null default now()
);

alter table public.app_users enable row level security;
alter table public.app_sessions enable row level security;
alter table public.training_stats enable row level security;
alter table public.questions enable row level security;

-- Remove o acesso direto usado na versão de login por email.
drop policy if exists "institutional users can read questions" on public.questions;
revoke all on public.questions from anon, authenticated;
revoke all on public.app_users from anon, authenticated;
revoke all on public.app_sessions from anon, authenticated;
revoke all on public.training_stats from anon, authenticated;

-- Administrador inicial. Se já tiver sido ativado, voltar a executar este script não repõe o PIN.
insert into public.app_users(mechanical_no, display_name, active, is_admin, activation_hash)
values ('202688', 'Administrador', true, true, extensions.crypt('08827412', extensions.gen_salt('bf', 10)))
on conflict (mechanical_no) do update
set is_admin=true,
    active=true,
    display_name=coalesce(public.app_users.display_name, excluded.display_name),
    activation_hash=case when public.app_users.pin_hash is null then excluded.activation_hash else public.app_users.activation_hash end;

create or replace function public._session_user(p_token text)
returns text
language sql
stable
security definer
set search_path = public, extensions
as $$
  select s.mechanical_no
  from public.app_sessions s
  join public.app_users u on u.mechanical_no=s.mechanical_no
  where s.token_hash=extensions.digest(coalesce(p_token,''),'sha256')
    and s.expires_at > now()
    and u.active=true
  limit 1;
$$;

create or replace function public._session_is_admin(p_token text)
returns boolean
language sql
stable
security definer
set search_path = public, extensions
as $$
  select coalesce((select u.is_admin
    from public.app_users u
    where u.mechanical_no=public._session_user(p_token)), false);
$$;

create or replace function public._new_session(p_mechanical text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare v_token text;
begin
  v_token := encode(extensions.gen_random_bytes(32),'hex');
  insert into public.app_sessions(token_hash, mechanical_no, expires_at)
  values (extensions.digest(v_token,'sha256'), p_mechanical, now()+interval '30 days');
  return v_token;
end;
$$;

create or replace function public.api_activate(p_mechanical text, p_activation_code text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare u public.app_users%rowtype; v_token text; v_attempts integer;
begin
  if p_mechanical !~ '^[0-9]{6}$' then return jsonb_build_object('ok',false,'error','invalid_number'); end if;
  if p_pin !~ '^[0-9]{4,6}$' then return jsonb_build_object('ok',false,'error','invalid_pin'); end if;
  if p_activation_code !~ '^[0-9]{8}$' then return jsonb_build_object('ok',false,'error','invalid_code'); end if;
  select * into u from public.app_users where mechanical_no=p_mechanical for update;
  if not found then return jsonb_build_object('ok',false,'error','not_authorized'); end if;
  if not u.active then return jsonb_build_object('ok',false,'error','inactive'); end if;
  if u.pin_hash is not null then return jsonb_build_object('ok',false,'error','already_activated'); end if;
  if u.locked_until is not null and u.locked_until>now() then return jsonb_build_object('ok',false,'error','locked'); end if;
  if u.activation_hash is null or extensions.crypt(p_activation_code,u.activation_hash)<>u.activation_hash then
    v_attempts:=u.failed_attempts+1;
    update public.app_users set failed_attempts=v_attempts,
      locked_until=case when v_attempts>=5 then now()+interval '15 minutes' else locked_until end
      where mechanical_no=p_mechanical;
    return jsonb_build_object('ok',false,'error','invalid_activation');
  end if;
  update public.app_users set pin_hash=extensions.crypt(p_pin,extensions.gen_salt('bf',10)), activation_hash=null,
    activated_at=coalesce(activated_at,now()), failed_attempts=0, locked_until=null, last_login_at=now()
    where mechanical_no=p_mechanical;
  insert into public.training_stats(mechanical_no) values(p_mechanical) on conflict do nothing;
  v_token:=public._new_session(p_mechanical);
  return jsonb_build_object('ok',true,'token',v_token,'mechanical_no',p_mechanical,'display_name',u.display_name,'is_admin',u.is_admin);
end;
$$;

create or replace function public.api_login(p_mechanical text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare u public.app_users%rowtype; v_token text; v_attempts integer;
begin
  if p_mechanical !~ '^[0-9]{6}$' then return jsonb_build_object('ok',false,'error','invalid_number'); end if;
  if p_pin !~ '^[0-9]{4,6}$' then return jsonb_build_object('ok',false,'error','invalid_pin'); end if;
  select * into u from public.app_users where mechanical_no=p_mechanical for update;
  if not found then return jsonb_build_object('ok',false,'error','not_authorized'); end if;
  if not u.active then return jsonb_build_object('ok',false,'error','inactive'); end if;
  if u.pin_hash is null then return jsonb_build_object('ok',false,'error','activation_required'); end if;
  if u.locked_until is not null and u.locked_until>now() then return jsonb_build_object('ok',false,'error','locked'); end if;
  if extensions.crypt(p_pin,u.pin_hash)<>u.pin_hash then
    v_attempts:=u.failed_attempts+1;
    update public.app_users set failed_attempts=v_attempts,
      locked_until=case when v_attempts>=5 then now()+interval '15 minutes' else locked_until end
      where mechanical_no=p_mechanical;
    return jsonb_build_object('ok',false,'error','wrong_pin');
  end if;
  update public.app_users set failed_attempts=0,locked_until=null,last_login_at=now() where mechanical_no=p_mechanical;
  v_token:=public._new_session(p_mechanical);
  return jsonb_build_object('ok',true,'token',v_token,'mechanical_no',p_mechanical,'display_name',u.display_name,'is_admin',u.is_admin);
end;
$$;

create or replace function public.api_session_info(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare v_mech text; u public.app_users%rowtype;
begin
  v_mech:=public._session_user(p_token);
  if v_mech is null then return jsonb_build_object('ok',false,'error','invalid_session'); end if;
  select * into u from public.app_users where mechanical_no=v_mech;
  return jsonb_build_object('ok',true,'mechanical_no',v_mech,'display_name',u.display_name,'is_admin',u.is_admin);
end;
$$;

create or replace function public.api_logout(p_token text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  delete from public.app_sessions where token_hash=extensions.digest(coalesce(p_token,''),'sha256');
  return true;
end;
$$;

create or replace function public.api_get_questions(p_token text)
returns table(id integer,question text,answers jsonb,correct integer,topic text,subtopic text,difficulty integer,explanation text,source text)
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if public._session_user(p_token) is null then raise exception 'Sessão inválida'; end if;
  return query select q.id,q.question,q.answers,q.correct,q.topic,q.subtopic,q.difficulty,q.explanation,q.source from public.questions q order by q.id;
end;
$$;

create or replace function public.api_get_stats(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare v_mech text; v_stats jsonb;
begin
  v_mech:=public._session_user(p_token);
  if v_mech is null then raise exception 'Sessão inválida'; end if;
  select stats into v_stats from public.training_stats where mechanical_no=v_mech;
  return coalesce(v_stats,'{"byQuestion":{},"history":[],"bookmarks":[]}'::jsonb);
end;
$$;

create or replace function public.api_save_stats(p_token text, p_stats jsonb)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare v_mech text;
begin
  v_mech:=public._session_user(p_token);
  if v_mech is null then raise exception 'Sessão inválida'; end if;
  if p_stats is null or jsonb_typeof(p_stats)<>'object' then raise exception 'Dados inválidos'; end if;
  insert into public.training_stats(mechanical_no,stats,updated_at) values(v_mech,p_stats,now())
  on conflict(mechanical_no) do update set stats=excluded.stats,updated_at=now();
  return true;
end;
$$;

create or replace function public.api_admin_list_users(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not public._session_is_admin(p_token) then raise exception 'Sem permissão'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object(
    'mechanical_no',u.mechanical_no,'display_name',u.display_name,'active',u.active,'is_admin',u.is_admin,
    'activated',(u.pin_hash is not null),'created_at',u.created_at,'last_login_at',u.last_login_at
  ) order by u.mechanical_no) from public.app_users u),'[]'::jsonb);
end;
$$;

create or replace function public.api_admin_add_user(p_token text,p_mechanical text,p_display_name text default null)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare v_code text;
begin
  if not public._session_is_admin(p_token) then raise exception 'Sem permissão'; end if;
  if p_mechanical !~ '^[0-9]{6}$' then return jsonb_build_object('ok',false,'error','invalid_number'); end if;
  if exists(select 1 from public.app_users where mechanical_no=p_mechanical) then return jsonb_build_object('ok',false,'error','exists'); end if;
  v_code:=lpad((floor(random()*100000000)::bigint)::text,8,'0');
  insert into public.app_users(mechanical_no,display_name,active,is_admin,activation_hash)
  values(p_mechanical,nullif(trim(p_display_name),''),true,false,extensions.crypt(v_code,extensions.gen_salt('bf',10)));
  return jsonb_build_object('ok',true,'mechanical_no',p_mechanical,'activation_code',v_code);
end;
$$;

create or replace function public.api_admin_reset_access(p_token text,p_mechanical text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare v_code text; v_admin text;
begin
  v_admin:=public._session_user(p_token);
  if v_admin is null or not public._session_is_admin(p_token) then raise exception 'Sem permissão'; end if;
  if p_mechanical=v_admin then return jsonb_build_object('ok',false,'error','cannot_reset_self'); end if;
  if not exists(select 1 from public.app_users where mechanical_no=p_mechanical) then return jsonb_build_object('ok',false,'error','not_found'); end if;
  v_code:=lpad((floor(random()*100000000)::bigint)::text,8,'0');
  update public.app_users set pin_hash=null,activation_hash=extensions.crypt(v_code,extensions.gen_salt('bf',10)),
    activated_at=null,failed_attempts=0,locked_until=null where mechanical_no=p_mechanical;
  delete from public.app_sessions where mechanical_no=p_mechanical;
  return jsonb_build_object('ok',true,'mechanical_no',p_mechanical,'activation_code',v_code);
end;
$$;

create or replace function public.api_admin_set_active(p_token text,p_mechanical text,p_active boolean)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare v_admin text;
begin
  v_admin:=public._session_user(p_token);
  if v_admin is null or not public._session_is_admin(p_token) then raise exception 'Sem permissão'; end if;
  if p_mechanical=v_admin and p_active=false then return jsonb_build_object('ok',false,'error','cannot_disable_self'); end if;
  update public.app_users set active=p_active where mechanical_no=p_mechanical;
  if not found then return jsonb_build_object('ok',false,'error','not_found'); end if;
  if p_active=false then delete from public.app_sessions where mechanical_no=p_mechanical; end if;
  return jsonb_build_object('ok',true);
end;
$$;

-- Privacidade: as tabelas não são consultadas diretamente pelo browser.
revoke all on function public._session_user(text) from public, anon, authenticated;
revoke all on function public._session_is_admin(text) from public, anon, authenticated;
revoke all on function public._new_session(text) from public, anon, authenticated;

revoke all on function public.api_activate(text,text,text) from public;
revoke all on function public.api_login(text,text) from public;
revoke all on function public.api_session_info(text) from public;
revoke all on function public.api_logout(text) from public;
revoke all on function public.api_get_questions(text) from public;
revoke all on function public.api_get_stats(text) from public;
revoke all on function public.api_save_stats(text,jsonb) from public;
revoke all on function public.api_admin_list_users(text) from public;
revoke all on function public.api_admin_add_user(text,text,text) from public;
revoke all on function public.api_admin_reset_access(text,text) from public;
revoke all on function public.api_admin_set_active(text,text,boolean) from public;

grant execute on function public.api_activate(text,text,text) to anon, authenticated;
grant execute on function public.api_login(text,text) to anon, authenticated;
grant execute on function public.api_session_info(text) to anon, authenticated;
grant execute on function public.api_logout(text) to anon, authenticated;
grant execute on function public.api_get_questions(text) to anon, authenticated;
grant execute on function public.api_get_stats(text) to anon, authenticated;
grant execute on function public.api_save_stats(text,jsonb) to anon, authenticated;
grant execute on function public.api_admin_list_users(text) to anon, authenticated;
grant execute on function public.api_admin_add_user(text,text,text) to anon, authenticated;
grant execute on function public.api_admin_reset_access(text,text) to anon, authenticated;
grant execute on function public.api_admin_set_active(text,text,boolean) to anon, authenticated;

-- Confirmação rápida no final.
select mechanical_no, display_name, active, is_admin, (pin_hash is not null) as activated
from public.app_users
order by mechanical_no;
