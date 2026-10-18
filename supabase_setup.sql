-- Cooldown Magazine FiveM — Supabase Auth + roluri și permisiuni
-- Înlocuiește PASTE_INITIAL_ADMIN_UUID_HERE cu UUID-ul primului administrator.
-- Rulează întregul fișier în Supabase Dashboard > SQL Editor > New query.
-- NU pune niciodată cheia secret/service_role în HTML.

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  is_admin boolean not null default false,
  can_start boolean not null default false,
  can_reset boolean not null default false,
  can_edit boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email)
  values (new.id, new.email)
  on conflict (id) do update set email = excluded.email;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

-- Sincronizează emailul când utilizatorul îl schimbă.
create or replace function public.handle_user_email_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if new.email is distinct from old.email then
    update public.profiles set email = new.email, updated_at = now() where id = new.id;
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_email_updated on auth.users;
create trigger on_auth_user_email_updated
after update of email on auth.users
for each row execute procedure public.handle_user_email_update();

-- Creează profile pentru conturile deja existente, apoi marchează primul admin.
insert into public.profiles (id, email)
select id, email from auth.users
on conflict (id) do update set email = excluded.email;

update public.profiles
set is_admin = true, can_start = true, can_reset = true, can_edit = true, updated_at = now()
where id = 'd7337ba0-88db-4c69-8378-6af13ed60b46'::uuid;

create or replace function public.is_site_admin()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.is_admin = true
  );
$$;

create table if not exists public.cooldown_timers (
  shop_id text primary key,
  started_at bigint not null,
  end_at bigint not null,
  constraint cooldown_timers_valid_shop check (shop_id in (
    'paleto','carduri','amanet','cnn-vechi','sectia-politie','groove','apa-mirror',
    'benzinarie-mirror','grapeseed','dedeman','pacific','dusty','diicot','highway'
  )),
  constraint cooldown_timers_valid_time check (end_at = started_at + 10800000)
);

alter table public.profiles enable row level security;
alter table public.cooldown_timers enable row level security;

-- Profilul propriu poate fi citit de utilizator; administratorul poate vedea toate profilele.
drop policy if exists "Users can read own profile" on public.profiles;
create policy "Users can read own profile" on public.profiles
for select to authenticated using (id = auth.uid());

drop policy if exists "Admins can read all profiles" on public.profiles;
create policy "Admins can read all profiles" on public.profiles
for select to authenticated using (public.is_site_admin());

-- Modificarea permisiunilor se face numai prin RPC-ul set_user_access.
revoke all on public.profiles from anon, authenticated;
grant select on public.profiles to authenticated;

-- Cronometrele sunt publice pentru citire, dar nu pot fi scrise direct din browser.
drop policy if exists "Anyone can view cooldown timers" on public.cooldown_timers;
create policy "Anyone can view cooldown timers" on public.cooldown_timers
for select to anon, authenticated using (true);

revoke all on public.cooldown_timers from anon, authenticated;
grant select on public.cooldown_timers to anon, authenticated;

create or replace function public.current_user_has_permission(permission_name text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.is_site_admin() or exists (
    select 1 from public.profiles p
    where p.id = auth.uid()
      and case permission_name
        when 'can_start' then p.can_start
        when 'can_reset' then p.can_reset
        when 'can_edit' then p.can_edit
        else false
      end
  );
$$;

create or replace function public.start_timer(p_shop_id text, p_started_at bigint, p_end_at bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not public.current_user_has_permission('can_start') then
    raise exception 'Nu ai permisiunea de a porni cronometre.';
  end if;
  if p_shop_id not in ('paleto','carduri','amanet','cnn-vechi','sectia-politie','groove','apa-mirror','benzinarie-mirror','grapeseed','dedeman','pacific','dusty','diicot','highway') then
    raise exception 'Magazin invalid.';
  end if;
  if p_end_at - p_started_at <> 10800000 or p_started_at < (extract(epoch from now()) * 1000)::bigint - 60000
     or p_started_at > (extract(epoch from now()) * 1000)::bigint + 60000 then
    raise exception 'Interval de timp invalid pentru pornire.';
  end if;
  if exists(select 1 from public.cooldown_timers where shop_id = p_shop_id and end_at > (extract(epoch from now()) * 1000)::bigint) then
    raise exception 'Cronometrul este deja activ.';
  end if;
  insert into public.cooldown_timers(shop_id, started_at, end_at)
  values (p_shop_id, p_started_at, p_end_at)
  on conflict (shop_id) do update set started_at = excluded.started_at, end_at = excluded.end_at;
end;
$$;

create or replace function public.edit_timer(p_shop_id text, p_started_at bigint, p_end_at bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not public.current_user_has_permission('can_edit') then
    raise exception 'Nu ai permisiunea de a edita cronometre.';
  end if;
  if p_end_at - p_started_at <> 10800000
     or p_end_at <= (extract(epoch from now()) * 1000)::bigint
     or p_end_at > (extract(epoch from now()) * 1000)::bigint + 10800000 then
    raise exception 'Timpul nou trebuie să fie între 1 și 180 de minute.';
  end if;
  update public.cooldown_timers set started_at = p_started_at, end_at = p_end_at where shop_id = p_shop_id;
  if not found then raise exception 'Cronometrul nu există.'; end if;
end;
$$;

create or replace function public.reset_timer(p_shop_id text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not public.current_user_has_permission('can_reset') then
    raise exception 'Nu ai permisiunea de a reseta cronometre.';
  end if;
  delete from public.cooldown_timers where shop_id = p_shop_id;
end;
$$;

create or replace function public.reset_all_timers()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not public.current_user_has_permission('can_reset') then
    raise exception 'Nu ai permisiunea de a reseta cronometre.';
  end if;
  delete from public.cooldown_timers;
end;
$$;

create or replace function public.replace_all_timers(p_timers jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  item record;
  v_start bigint;
  v_end bigint;
begin
  if auth.uid() is null
     or not public.current_user_has_permission('can_edit')
     or not public.current_user_has_permission('can_reset') then
    raise exception 'Ai nevoie de permisiunile de editare și resetare.';
  end if;
  if jsonb_typeof(p_timers) <> 'object' then raise exception 'Format de backup invalid.'; end if;
  for item in select key, value from jsonb_each(p_timers) loop
    if item.key not in ('paleto','carduri','amanet','cnn-vechi','sectia-politie','groove','apa-mirror','benzinarie-mirror','grapeseed','dedeman','pacific','dusty','diicot','highway') then
      raise exception 'Magazin invalid în backup.';
    end if;
    v_start := (item.value->>'startedAt')::bigint;
    v_end := (item.value->>'endAt')::bigint;
    if v_end - v_start <> 10800000 or v_start <= 0 then
      raise exception 'Interval invalid în backup.';
    end if;
  end loop;
  delete from public.cooldown_timers;
  insert into public.cooldown_timers(shop_id, started_at, end_at)
  select key, (value->>'startedAt')::bigint, (value->>'endAt')::bigint
  from jsonb_each(p_timers);
end;
$$;

-- Numai un administrator autentificat poate acorda/revoca roluri și permisiuni.
create or replace function public.set_user_access(
  p_user_id uuid,
  p_is_admin boolean,
  p_can_start boolean,
  p_can_reset boolean,
  p_can_edit boolean
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if auth.uid() is null or not public.is_site_admin() then
    raise exception 'Doar un administrator poate modifica accesul utilizatorilor.';
  end if;
  if p_user_id = auth.uid() and not p_is_admin then
    raise exception 'Nu îți poți revoca singur rolul de administrator.';
  end if;
  update public.profiles
  set is_admin = p_is_admin,
      can_start = case when p_is_admin then true else p_can_start end,
      can_reset = case when p_is_admin then true else p_can_reset end,
      can_edit = case when p_is_admin then true else p_can_edit end,
      updated_at = now()
  where id = p_user_id;
  if not found then raise exception 'Utilizatorul nu a fost găsit.'; end if;
end;
$$;

-- Permite apelurile doar utilizatorilor autentificați.
revoke all on function public.is_site_admin() from public, anon;
revoke all on function public.current_user_has_permission(text) from public, anon;
revoke all on function public.start_timer(text,bigint,bigint) from public, anon;
revoke all on function public.edit_timer(text,bigint,bigint) from public, anon;
revoke all on function public.reset_timer(text) from public, anon;
revoke all on function public.reset_all_timers() from public, anon;
revoke all on function public.replace_all_timers(jsonb) from public, anon;
revoke all on function public.set_user_access(uuid,boolean,boolean,boolean,boolean) from public, anon;
grant execute on function public.is_site_admin() to authenticated;
grant execute on function public.current_user_has_permission(text) to authenticated;
grant execute on function public.start_timer(text,bigint,bigint) to authenticated;
grant execute on function public.edit_timer(text,bigint,bigint) to authenticated;
grant execute on function public.reset_timer(text) to authenticated;
grant execute on function public.reset_all_timers() to authenticated;
grant execute on function public.replace_all_timers(jsonb) to authenticated;
grant execute on function public.set_user_access(uuid,boolean,boolean,boolean,boolean) to authenticated;

-- Restricții explicite pentru rolul anon: doar SELECT pe cronometre.
