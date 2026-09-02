-- ============================================================================
-- BRIDGE — MILESTONE 3.4
-- Role-based authorization foundation
-- ============================================================================

create type public.organization_type as enum (
    'brand',
    'retailer',
    'dispensary'
);

-- Nullable by design for the first rollout. Existing organizations require an
-- explicit classification decision before a future migration enforces NOT NULL.
alter table public.organizations
    add column organization_type public.organization_type;

create type public.user_account_type as enum (
    'standard',
    'sales_rep'
);

alter table public.user_profiles
    add column account_type public.user_account_type not null
        default 'standard';

-- The existing self-update RLS policy is row-scoped, not column-scoped.
-- Keep editable profile fields available without allowing account-type changes.
revoke update on public.user_profiles from authenticated;
grant update (display_name, phone) on public.user_profiles to authenticated;

create type public.platform_role as enum (
    'admin'
);

create table public.user_platform_roles (
    user_id uuid not null
        references auth.users(id)
        on delete cascade,
    role public.platform_role not null,
    created_at timestamptz not null
        default timezone('utc', now()),

    primary key (user_id, role)
);

alter table public.user_platform_roles enable row level security;

create policy user_platform_roles_select_self
on public.user_platform_roles
for select
to authenticated
using (
    user_id = (select auth.uid())
);

-- No INSERT, UPDATE, or DELETE policies are intentionally exposed to normal
-- authenticated users. Platform-role grants require a trusted admin workflow.

comment on column public.organizations.organization_type is
    'Business classification. Nullable until existing organizations are explicitly classified.';

comment on column public.user_profiles.account_type is
    'Non-privileged application account capability classification.';

comment on table public.user_platform_roles is
    'Explicit platform-level role assignments, separate from organization membership roles.';
