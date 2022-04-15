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

# Notes
- Remix Blues stack includes a `--require ./mocks` in the `dev:server` command to mock HTTP resources for local dev