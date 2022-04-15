-- CREATE DOMAIN email ...
create type image as (id uuid, ratio double precision);

create function app.is_email(value text) returns boolean
as $$
    select value ~ '[^@]+@[^@]+\.[^@]+';
$$ language sql immutable;

create domain email as citext
check(app.is_email(value));

create type auth_token as enum (
    'verify_email',
    'reset_password',
    'change_email',
    'delete_account'
);