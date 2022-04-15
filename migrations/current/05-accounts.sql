/*
  Processes:
  - email verification
  - email change
  - reset password
  - delete account
  - magic links (future)
*/
create table internal.accounts (
  id uuid primary key default gen_random_uuid(),
  -- nullable to enable magic links / OAuth2 providers in the future
  password_hash text,
  email email not null,
  last_login timestamptz not null default now(),

  verification_token text,
  verification_sent_at timestamptz,
  verified_at timestamptz,

  password_reset_token text,
  password_reset_sent_at timestamptz,

  email_change_token text,
  email_change_sent_at timestamptz,
  new_email email,

  delete_token text,
  delete_token_sent_at timestamptz,
  is_deleted boolean,
  
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Efficient search by email
create unique index unique_email on internal.accounts(email);
-- TODO: add constraints to prevent changing email to an already used email
-- & to handle the case where someone may request an email change,
-- but a new account using that email is created in the meantime?

-- Any read / mutation has to go through a security definer function
alter table internal.accounts enable row level security;

-- We can add the foreign key on sessions
alter table internal.sessions
  add constraint sessions_user_id_fkey
  foreign key("user_id") references internal.accounts on delete cascade;

create trigger timestamps
  before insert or update on internal.accounts
  for each row
  execute procedure internal.timestamps();
