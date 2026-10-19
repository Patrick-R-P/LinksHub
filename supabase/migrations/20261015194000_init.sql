-- =============================================================================
-- LinksHub: schema inicial
-- Perfis, páginas, seções, links, cliques + RLS, funções e storage.
-- =============================================================================

create extension if not exists citext with schema extensions;

-- -----------------------------------------------------------------------------
-- Utilitários
-- -----------------------------------------------------------------------------
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

-- Usernames que colidem com rotas do app.
create or replace function public.is_reserved_username(name text)
returns boolean
language sql
immutable
as $$
  select lower(name) = any (array[
    'admin','api','app','auth','dashboard','login','logout','signup','register',
    'onboarding','settings','r','static','public','_next','favicon.ico','robots.txt',
    'sitemap.xml','help','support','about','terms','privacy','linkshub','www'
  ]);
$$;

-- -----------------------------------------------------------------------------
-- profiles (1:1 com auth.users)
-- -----------------------------------------------------------------------------
create table public.profiles (
  id           uuid primary key references auth.users (id) on delete cascade,
  username     extensions.citext unique,
  display_name text check (char_length(display_name) <= 60),
  avatar_url   text,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now(),
  constraint username_format check (
    username is null or (
      username ~ '^[a-z0-9](?:[a-z0-9_.-]{1,28})[a-z0-9]$'
      and not public.is_reserved_username(username::text)
    )
  )
);

create trigger profiles_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();

-- Cria o perfil automaticamente no cadastro (e-mail ou Google).
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, display_name, avatar_url)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', new.raw_user_meta_data ->> 'name'),
    new.raw_user_meta_data ->> 'avatar_url'
  );
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- -----------------------------------------------------------------------------
-- pages
-- -----------------------------------------------------------------------------
create table public.pages (
  id           uuid primary key default gen_random_uuid(),
  owner_id     uuid not null references public.profiles (id) on delete cascade,
  title        text not null default '' check (char_length(title) <= 80),
  bio          text not null default '' check (char_length(bio) <= 300),
  avatar_url   text,
  theme        jsonb not null default '{}'::jsonb,
  seo          jsonb not null default '{}'::jsonb,
  is_published boolean not null default true,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

-- Por enquanto: uma página por usuário (remover este índice para permitir várias).
create unique index pages_one_per_owner on public.pages (owner_id);

create trigger pages_updated_at
  before update on public.pages
  for each row execute function public.set_updated_at();

-- -----------------------------------------------------------------------------
-- sections
-- -----------------------------------------------------------------------------
create table public.sections (
  id         uuid primary key default gen_random_uuid(),
  page_id    uuid not null references public.pages (id) on delete cascade,
  title      text not null default '' check (char_length(title) <= 60),
  icon       jsonb,
  layout     text not null default 'list' check (layout in ('list','grid','carousel','icons')),
  position   integer not null default 0,
  is_visible boolean not null default true,
  style      jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index sections_page_position on public.sections (page_id, position);

create trigger sections_updated_at
  before update on public.sections
  for each row execute function public.set_updated_at();

-- -----------------------------------------------------------------------------
-- links
-- -----------------------------------------------------------------------------
create table public.links (
  id         uuid primary key default gen_random_uuid(),
  section_id uuid not null references public.sections (id) on delete cascade,
  title      text not null check (char_length(title) between 1 and 80),
  url        text not null check (url ~* '^(https?://|mailto:|tel:)' and char_length(url) <= 2048),
  icon       jsonb,
  position   integer not null default 0,
  is_visible boolean not null default true,
  highlight  boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index links_section_position on public.links (section_id, position);

create trigger links_updated_at
  before update on public.links
  for each row execute function public.set_updated_at();

-- -----------------------------------------------------------------------------
-- link_clicks
-- -----------------------------------------------------------------------------
create table public.link_clicks (
  id         bigint generated always as identity primary key,
  link_id    uuid not null references public.links (id) on delete cascade,
  clicked_at timestamptz not null default now(),
  referrer   text,
  country    text
);

create index link_clicks_link_time on public.link_clicks (link_id, clicked_at desc);

-- =============================================================================
-- Row Level Security
-- =============================================================================
alter table public.profiles    enable row level security;
alter table public.pages       enable row level security;
alter table public.sections    enable row level security;
alter table public.links       enable row level security;
alter table public.link_clicks enable row level security;

-- profiles: username/nome/avatar são públicos; só o dono altera.
create policy "profiles: leitura pública" on public.profiles
  for select using (true);
create policy "profiles: dono atualiza" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

-- pages
create policy "pages: publicadas ou do dono" on public.pages
  for select using (is_published or (select auth.uid()) = owner_id);
create policy "pages: dono cria" on public.pages
  for insert to authenticated with check ((select auth.uid()) = owner_id);
create policy "pages: dono atualiza" on public.pages
  for update to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy "pages: dono remove" on public.pages
  for delete to authenticated using ((select auth.uid()) = owner_id);

-- Helpers (security definer evita recursão de RLS e é mais rápido).
create or replace function public.owns_page(p_page_id uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.pages p
    where p.id = p_page_id and p.owner_id = (select auth.uid())
  );
$$;

create or replace function public.owns_section(p_section_id uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1 from public.sections s
    join public.pages p on p.id = s.page_id
    where s.id = p_section_id and p.owner_id = (select auth.uid())
  );
$$;

create or replace function public.page_is_public(p_page_id uuid)
returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (select 1 from public.pages p where p.id = p_page_id and p.is_published);
$$;

-- sections
create policy "sections: leitura" on public.sections
  for select using (
    public.owns_page(page_id) or (is_visible and public.page_is_public(page_id))
  );
create policy "sections: dono cria" on public.sections
  for insert to authenticated with check (public.owns_page(page_id));
create policy "sections: dono atualiza" on public.sections
  for update to authenticated
  using (public.owns_page(page_id)) with check (public.owns_page(page_id));
create policy "sections: dono remove" on public.sections
  for delete to authenticated using (public.owns_page(page_id));

-- links
create policy "links: leitura" on public.links
  for select using (
    public.owns_section(section_id)
    or (
      is_visible and exists (
        select 1 from public.sections s
        where s.id = section_id and s.is_visible and public.page_is_public(s.page_id)
      )
    )
  );
create policy "links: dono cria" on public.links
  for insert to authenticated with check (public.owns_section(section_id));
create policy "links: dono atualiza" on public.links
  for update to authenticated
  using (public.owns_section(section_id)) with check (public.owns_section(section_id));
create policy "links: dono remove" on public.links
  for delete to authenticated using (public.owns_section(section_id));

-- link_clicks: somente leitura pelo dono; inserção apenas via record_click().
create policy "link_clicks: dono lê" on public.link_clicks
  for select to authenticated using (
    exists (select 1 from public.links l where l.id = link_id and public.owns_section(l.section_id))
  );

-- =============================================================================
-- RPCs
-- =============================================================================

-- Reordena seções de uma página na ordem do array (RLS aplicada: security invoker).
create or replace function public.reorder_sections(p_page_id uuid, p_ids uuid[])
returns void
language plpgsql security invoker set search_path = ''
as $$
begin
  if not public.owns_page(p_page_id) then
    raise exception 'not allowed' using errcode = '42501';
  end if;

  update public.sections s
     set position = o.ord - 1
    from unnest(p_ids) with ordinality as o(id, ord)
   where s.id = o.id and s.page_id = p_page_id;
end;
$$;

-- Define a lista/ordem de links de uma seção (permite mover links entre seções).
create or replace function public.move_links(p_section_id uuid, p_ids uuid[])
returns void
language plpgsql security invoker set search_path = ''
as $$
begin
  if not public.owns_section(p_section_id) then
    raise exception 'not allowed' using errcode = '42501';
  end if;

  update public.links l
     set section_id = p_section_id,
         position   = o.ord - 1
    from unnest(p_ids) with ordinality as o(id, ord)
   where l.id = o.id
     and public.owns_section(l.section_id); -- só links do próprio usuário
end;
$$;

-- Registra um clique e devolve a URL de destino (null se link não for público).
create or replace function public.record_click(p_link_id uuid, p_referrer text default null)
returns text
language plpgsql security definer set search_path = ''
as $$
declare
  v_url text;
begin
  select l.url into v_url
    from public.links l
    join public.sections s on s.id = l.section_id
    join public.pages p on p.id = s.page_id
   where l.id = p_link_id and l.is_visible and s.is_visible and p.is_published;

  if v_url is null then
    return null;
  end if;

  insert into public.link_clicks (link_id, referrer)
  values (p_link_id, left(p_referrer, 500));

  return v_url;
end;
$$;

revoke execute on function public.record_click(uuid, text) from public;
grant execute on function public.record_click(uuid, text) to anon, authenticated;
revoke execute on function public.reorder_sections(uuid, uuid[]) from public, anon;
grant execute on function public.reorder_sections(uuid, uuid[]) to authenticated;
revoke execute on function public.move_links(uuid, uuid[]) from public, anon;
grant execute on function public.move_links(uuid, uuid[]) to authenticated;

-- =============================================================================
-- Storage: avatares (pasta por usuário: {uid}/arquivo)
-- =============================================================================
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('avatars', 'avatars', true, 2097152, array['image/png','image/jpeg','image/webp','image/gif'])
on conflict (id) do nothing;

create policy "avatars: leitura pública" on storage.objects
  for select using (bucket_id = 'avatars');
create policy "avatars: dono envia" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "avatars: dono atualiza" on storage.objects
  for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "avatars: dono remove" on storage.objects
  for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
