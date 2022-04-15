create function internal.new_token() returns text as $$
  select encode(gen_random_bytes(16), 'hex');
$$ language sql volatile;

/* Checks
 * - Only modifies the current user
 * - Matches the token with one in the table
 * - Checks that the email is not verified yet
 */
create function app.verify_email(token text) returns boolean as $$
begin
    update internal.accounts
    set
        verification_token = null,
        verified_at = NOW()
    where id = app.user()
    and verification_token = token;
    return found;
end;
$$ language plpgsql strict volatile security definer set search_path to pg_catalog, public, pg_temp;

create function app.is_verified() returns boolean as $$
  select exists(
    select 1 from internal.accounts
    where verified_at is not null
    and id = app.user()
  );
$$ language sql stable security definer set search_path to pg_catalog, public, pg_temp;

/* SECURITY NOTE
 * The system allows unlimited login attempts for now.
 * In practice, our accounts do not serve any critical purpose, so it's fine
 * In case this needs to be implemented later:
 * - remove the `app.login` function, as an external user could try to login
 *   + fail the transaction to avoid increasing the failed attempts count
 * - add a new `internal.login` function
 */

create function app.login(username citext, password text) returns internal.sessions as $$
declare
    v_user app.users;
    v_account internal.accounts;
    v_session internal.sessions;
begin
    if app.is_email(username) then
        select * into v_account
        from internal.accounts
        where accounts.email = login.username;
    else
        select * into v_user
        from app.users
        where users.username = login.username;

        select * into v_account
        from internal.accounts
        where accounts.id = v_user.id;
    end if;

    -- We're not keeping track of failed login attempts, so we can abort the transaction early by throwing
    
    -- Return same error as for wrong password, for security
    if(v_account is null) then
        raise exception 'Wrong credentials' using errcode = 'CREDS';
    end if;

    if(v_account.verified_at is null) then
        raise exception 'Please verify your email to login.' using errcode = 'NOTVERIF';
    end if;

    -- Note: `null = null` returns null, which is falsy
    if(v_account.password_hash = crypt(password, v_account.password_hash)) then
        -- Success!
        update internal.accounts
        set last_login = NOW()
        where id = v_account.id;

        insert into internal.sessions(user_id)
        values (v_account.id)
        returning * into v_session;

        return v_session;
    else 
        raise exception 'Wrong credentials' using errcode = 'CREDS';
    end if;
end;
$$ language plpgsql strict volatile security definer set search_path to pg_catalog, public, pg_temp;

create function app.logout() returns void as $$
begin
    delete from internal.sessions
    where id = app.session();
    -- clear the identifier from the transaction
    perform set_config('jwt.claims.session_id', '', true);
end;
$$ language plpgsql security definer set search_path to pg_catalog, public, pg_temp;

/* SECURITY NOTE
 * If the application grows, we should start tracking reset attempts,
 * to detect accounts that are being attacked.
 * We should also keep track of password reset attempts for unregistered emails,
 * for logging purposes.
 * If we need better logging, we should distinguish between reset token generation time,
 * and the time of the last reset email we sent.
 *
 * For now, we only make sure that we don't reveal whether the email is registered or not.
 */
create function app.forgot_password(email citext) returns void as $$
declare
    v_account internal.accounts;
    v_token_min_interval interval = interval '60 seconds';
    v_token_expires interval = interval '3 hours';
    v_token text;
begin
    select * into v_account
    from internal.accounts
    where accounts.email = forgot_password.email;

    -- No matching account
    if(v_account is null) then
      return;
    end if;

    -- Check if we already sent an email recently
    if (
        v_account.password_reset_sent_at is not null
        and NOW() < v_account.password_reset_sent_at + v_token_min_interval
    ) then
        -- TODO: raise exception?
        return;
    end if;

    -- Fetch or generate reset token
    update internal.accounts
    set 
      password_reset_token = (
          case
          when password_reset_token is null or NOW() > password_reset_sent_at + v_token_expires
          then internal.new_token()
          else password_reset_token
          end
      ),
      -- Doubles as a generation time (i.e. is not updated for overlapping requests)
      password_reset_sent_at = (
          case
          when password_reset_token is null or NOW() > password_reset_sent_at + v_token_expires
          then NOW()
          else password_reset_sent_at
          end
      )
    where id = v_account.id
    returning password_reset_token into v_token;

    -- Schedule job
    perform graphile_worker.add_job(
      'forgot_password',
      json_build_object('id', v_account.id, 'email', v_account.email::text, 'token', v_token)
    );
end;
$$ language plpgsql strict volatile security definer set search_path to pg_catalog, public, pg_temp;

create function internal.assert_valid_password(password text) returns void as $$
begin
  if length(password < 6) then 
    raise exception 'Password is too weak' using errcode = 'WEAKPASS';
  end if;
end;
$$ language plpgsql volatile;

/* SECURITY NOTE
 * A more secure setup would keep track of the number of reset attempts w/ incorrect tokens,
 * to deny brute force attacks.
 */
create function app.reset_password(user_id uuid, reset_token text, new_password text) returns boolean as $$
declare
  v_account internal.accounts;
  v_token_expires interval = interval '3 hours';
begin
  select * into v_account 
  from internal.accounts
  where id = user_id;

  if (
    v_account is null
    or v_account.password_reset_token is null
    or v_account.password_reset_token <> reset_token
  ) then
    return false;
  end if;

  if (now() > v_account.password_reset_sent_at + v_token_expires) then
    raise exception 'Expired token' using errcode = 'EXP_TOKEN';
  end if;

  perform internal.assert_valid_password(new_password);

  -- Perform reset
  update internal.accounts
  set
    password_hash = crypt(new_password, gen_salt('bf')),
    password_reset_token = null,
    password_reset_sent_at = null
  where accounts.id = v_account.id;

  -- Revoke all existing sessions
  delete from internal.sessions
  where sessions.user_id = v_account.id;

  -- Notify the user their password was changed
  perform graphile_worker.add_job(
    'password_changed',
    json_build_object('id', v_account.id, 'email', v_account.email)
  );

  return true;
end;
$$ language plpgsql strict volatile security definer set search_path to pg_catalog, public, pg_temp;


create function app.request_account_deletion() returns void as $$
declare
  v_id uuid;
  v_email citext;
  v_token text;
  v_token_expires interval = interval '3 hours';
begin
  update internal.accounts
  set
    delete_token = (
      case
      when delete_token is null or NOW() > delete_token_sent_at + v_token_expires
      then internal.new_token()
      else delete_token
      end
    ),
    -- Doubles as a generation time (i.e. is not updated for overlapping requests)
    delete_token_sent_at = (
      case
      when delete_token is null or NOW() > delete_token_sent_at + v_token_expires
      then now()
      else delete_token_sent_at
      end
    )
  where id = app.user()
  returning id, email, delete_token into v_id, v_email, v_token;

  -- Account not found
  if(v_token is null) then
    raise exception 'You must be logged in to delete your account' using errcode = 'LOGIN';
  end if;

  perform graphile_worker.add_job(
    'request_account_deletion',
    json_build_object('id', v_id, 'email', v_email, 'token', v_token)
  );
end;
$$ language plpgsql volatile security definer set search_path to pg_catalog, public, pg_temp;

create function app.confirm_account_deletion(token text) returns boolean as $$
declare
  v_account internal.accounts;
  v_token_expires interval = interval '3 hours';
begin
  if (app.user() is null) then
    raise exception 'You must be logged in to delete your account' using errcode = 'LOGIN';
  end if;

  select * into v_account
  from internal.accounts
  where id = app.user();

  -- Check if the account was already deleted
  if (v_account is null) then
    return true;
  end if;


  if (
    v_account.delete_token = token
    and now() < v_account.delete_token_sent_at + v_token_expires
  ) then
    -- The delete cascades
    delete from internal.accounts
    where id = v_account.id;

    return true;
  else
    raise exception 'Invalid token' using errcode = 'EXP_TOKEN';
  end if;
end;
$$ language plpgsql strict volatile security definer set search_path to pg_catalog, public, pg_temp;


create function app.change_password(old_password text, new_password text) returns boolean as $$
declare
  v_account internal.accounts;
begin
  select * into v_account
  from internal.accounts
  where id = app.user();

  if (v_account is null) then
    raise exception 'Must be logged in to change password!' using errcode = 'LOGIN';
  end if;

  -- Reminder: null = null -> null -> falsy value
  if (v_account.password_hash = crypt(old_password, v_account.password_hash)) then 
    -- OK, we can change the password
    update internal.accounts
    set
      password_hash = crypt(new_password, gen_salt('bf'))
    where id = v_account.id;

    -- Revoke all other sessions
    delete from internal.sessions
    where sessions.user_id = v_account.id
    and sessions.id <> app.session();

    -- Notify the user
    perform graphile_worker.add_job(
      'password_changed',
      json_build_object('id', v_account.id, 'email', v_account.email)
    );

    return true;
  else
    raise exception 'Wrong password' using errcode = 'CREDS';
  end if;

end;
$$ language plpgsql strict volatile security definer set search_path to pg_catalog, public, pg_temp;

create function app.signup(
  email citext,
  password text,
  username citext
) returns boolean as $$
declare
  v_token text;
  v_id uuid;
begin
  v_token := internal.new_token();

  -- TODO: check, does this raise an exception as expected when email
  -- or username is already taken?
  insert into internal.accounts (email, password_hash, verification_token)
  values (
    signup.email,
    crypt(signup.password, gen_salt('bf')),
    v_token
  )
  returning id into v_id;

  insert into app.users (id, username)
  values (v_id, signup.username);

  perform graphile_worker.add_job(
    'verify_email',
    json_build_object('id', v_id, 'email', email, 'token', v_token)
  );

  return true;
end;
$$ language plpgsql strict security definer set search_path to pg_catalog, public, pg_temp;

create function app.resend_verification(email citext) returns boolean as $$
declare
  v_account internal.accounts;
begin
  select * into v_account 
  from internal.accounts
  where accounts.email = resend_verification.email;

  if (
    v_account is not null )
end;
$$ language plpgsql strict security definer set search_path to pg_catalog, public, pg_temp;