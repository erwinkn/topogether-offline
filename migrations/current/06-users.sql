-- Public information
create table app.users (
  id uuid primary key references internal.accounts(id) on delete cascade,
  username citext not null unique check(
    length(username) >= 2
    and length(username) <= 80
  ),
  is_admin boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  name varchar(255),
  image image,
  city varchar(255),
  country varchar(255)
);

alter table app.users enable row level security;

-- View everyone, update yourself
create policy select_all on app.users for select using (true);
create policy update_self on app.users for update using (id = app.user());

grant select on app.users to :DATABASE_VISITOR;
grant update(username, name, image, city, country) on app.users to :DATABASE_VISITOR;
-- inserts and deletes handled separately

create trigger timestamp_users
  before insert or update on app.users
  for each row
  execute procedure internal.timestamps();

create function app.profile() returns app.users as $$
  select * from app.users
  where id = app.user();
$$ language sql stable;


-- Used to display different forms (change or set password) based on user account
create function app.users_has_password(u app.users) returns boolean as $$
  select (password_hash is not null)
  from internal.accounts
  where accounts.id = u.id
  and u.id = app.user();
$$ language sql stable security definer set search_path to pg_catalog, public, pg_temp;