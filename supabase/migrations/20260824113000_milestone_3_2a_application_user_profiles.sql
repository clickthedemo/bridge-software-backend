-- ============================================================================
-- BRIDGE — MILESTONE 3.2A
-- Application user profiles
--
-- The table was introduced in Milestone 2 with `user_id` as its primary key.
-- This incremental migration aligns it with the Milestone 3 profile contract
-- and moves profile provisioning behind a trusted auth.users trigger.
-- ============================================================================

alter table public.user_profiles
    rename column user_id to id;

alter table public.user_profiles enable row level security;

drop policy if exists user_profiles_select_self
    on public.user_profiles;

drop policy if exists user_profiles_insert_self
    on public.user_profiles;

drop policy if exists user_profiles_update_self
    on public.user_profiles;

create policy user_profiles_select_self
on public.user_profiles
for select
to authenticated
using (
    id = (select auth.uid())
);

create policy user_profiles_update_self
on public.user_profiles
for update
to authenticated
using (
    id = (select auth.uid())
)
with check (
    id = (select auth.uid())
);

create or replace function public.handle_new_user_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
    insert into public.user_profiles (id)
    values (new.id)
    on conflict (id) do nothing;

    return new;
end;
$$;

revoke all on function public.handle_new_user_profile() from public;
revoke all on function public.handle_new_user_profile() from anon;
revoke all on function public.handle_new_user_profile() from authenticated;

drop trigger if exists auth_users_create_profile on auth.users;

create trigger auth_users_create_profile
after insert on auth.users
for each row
execute function public.handle_new_user_profile();

-- Provision profiles for auth users created before this trigger existed.
insert into public.user_profiles (id)
select users.id
from auth.users as users
on conflict (id) do nothing;

comment on function public.handle_new_user_profile() is
    'Provision a minimal application profile after a Supabase Auth user is created.';
