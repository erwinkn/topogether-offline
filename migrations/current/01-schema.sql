--! Reset
drop schema if exists app cascade;
drop schema if exists hidden cascade;
drop schema if exists internal cascade;

--! Public permissions
/*
 * The `public` *schema* contains things like PostgreSQL extensions. We
 * deliberately do not install application logic into the public schema
 * (instead storing it to app/hidden/internal as appropriate),
 * but none the less we don't want untrusted roles to be able to install or
 * modify things into the public schema.
 *
 * The `public` *role* is automatically inherited by all other roles; we only
 * want specific roles to be able to access our database so we must revoke
 * access to the `public` role.
 */

revoke all on schema public from public;

alter default privileges revoke all on sequences from public;
alter default privileges revoke all on functions from public;

grant all on schema public to :DATABASE_OWNER;

--! Schemas
create schema app;
create schema hidden;
create schema internal;

-- The 'visitor' role (used by PostGraphile to represent an end user) may
-- access the public, app and hidden schemas (NOT internal)
grant usage on schema public, app, hidden to :DATABASE_VISITOR;

-- We want the `visitor` role to be able to insert rows (`serial` data type
-- creates sequences, so we need to grant access to that).
alter default privileges in schema public, app, hidden
    grant usage, select on sequences to :DATABASE_VISITOR;

-- And the `visitor` role should be able to call functions too.
alter default privileges in schema public, app, hidden
  grant execute on functions to :DATABASE_VISITOR;

--! Extensions
create extension if not exists citext with schema public;
create extension if not exists pgcrypto with schema public;

