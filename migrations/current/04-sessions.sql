/* This table is *only* used by `connect-pg-simple` to track
 * cookie session information.
 */
create table internal.connect_pg_simple_sessions (
    sid varchar primary key,
    sess json not null,
    expire timestamp not null
);
alter table internal.connect_pg_simple_sessions enable row level security;

create index pg_simple_session_expires on internal.connect_pg_simple_sessions (expire);

-- TODO: is this ID the same as the sid above?
create table internal.sessions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null, -- foreign key constraint added later
    created_at timestamptz not null default now(),
    last_active timestamptz not null default now()
);
-- efficient search
create index on internal.sessions (user_id);
-- RLS
alter table internal.sessions enable row level security;

-- The two functions below are kept in `app` for debugging purposes,
-- but hidden through the use of PostGraphile smart tags.

-- Note: we also use `jwt.claims.session_id` for non-JWT sessions to ensure interoperability
create function app.session() returns uuid as $$
  select nullif(pg_catalog.current_setting('jwt.claims.session_id', true), '')::uuid;
$$ language sql stable;

create function app.user() returns uuid as $$
  select user_id from internal.sessions where id = app.session();
$$ language sql stable security definer set search_path to pg_catalog, public, pg_temp;
