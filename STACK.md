# Ideal backend stack
## Authentication
- Use DB sessions: http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/
    -> we need additional data to render customised pages anyways
    -> can't store `role: 'admin'` or `picture: ...` in a JWT without the risk of it going stale
    -> sessions can be revoked (on password change for instance)
- Basically: JWTs are good as single-use tokens, or to interoperate with OAuth + store session information   
- Use CSRF tokens:
## Authorization
Authorization is defined directly in Postres, using roles, grants and row-level security.

Postgres roles:
- `webuser`
- `webadmin`
- `postgres`

Flow for each request:
- Begin transaction
- Call an authentication function, which validates the session information against the DB
- If not successful, abort transaction and return error
- Set up the Postgres role for the session & return the user information
- Proceed with the rest of the work
## DB setup
- Heavily inspired from the Graphile starter for the user sessions
- Use `language sql` as much as possible for functions, as those can be inlined at the call site
- all `security definer` functions should define `set search_path from current`
  due to `CVE-2018-1058`
- `@omit` smart comments should not be used for permissions, instead deferring
  to PostGraphile's RBAC support
- all tables (public or not) should enable RLS
- relevant RLS policy should be defined before granting a permission
- `grant select` should never specify a column list; instead use one-to-one
  relations as permission boundaries
- `grant insert` and `grant update` must ALWAYS specify a column list

# Notes
- Remix Blues stack includes a `--require ./mocks` in the `dev:server` command to mock HTTP resources for local dev

# TODOS
- Add Graphile worker jobs (see Graphile starter)
- Move session information to Redis, instead of a Postgres table
  - see Graphile Starter
  - https://medium.com/mtholla/managing-node-js-express-sessions-with-redis-94cd099d6f2f

- Write up Postgres guide, with tips and tricks