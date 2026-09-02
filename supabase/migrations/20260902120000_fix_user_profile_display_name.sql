begin;

create or replace function public.handle_new_user_profile()
returns trigger
language plpgsql
security definer
set search_path = ''
as $function$
begin
    insert into public.user_profiles (id, display_name)
    values (
        new.id,
        nullif(trim(new.raw_user_meta_data ->> 'display_name'), '')
    )
    on conflict (id) do update
    set display_name = excluded.display_name
    where public.user_profiles.display_name is null
      and excluded.display_name is not null;

    return new;
end;
$function$;

update public.user_profiles as profile
set display_name = nullif(
    trim(auth_user.raw_user_meta_data ->> 'display_name'),
    ''
)
from auth.users as auth_user
where profile.id = auth_user.id
  and profile.display_name is null
  and nullif(
      trim(auth_user.raw_user_meta_data ->> 'display_name'),
      ''
  ) is not null;

commit;
