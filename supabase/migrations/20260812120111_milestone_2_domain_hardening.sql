-- ============================================================================
-- BRIDGE — MILESTONE 2
-- Domain Hardening
--
-- Adds:
--   1. Application user profiles
--   2. Organization locations
--   3. Verification item history
--   4. Verification item/document relationships
--   5. RBAC helper functions
--   6. Hardened verification/document RLS
--
-- Intentionally NOT included:
--   - Full EIN storage
--   - Automated cannabis registry model
--   - Provider-specific API credentials
--   - Platform-admin role model
--
-- Those require separate architectural decisions.
-- ============================================================================


-- ============================================================================
-- 1. USER PROFILES
--
-- Supabase Auth owns authentication in auth.users.
-- This table owns application-level user information.
-- ============================================================================

create table public.user_profiles (
    user_id uuid primary key
        references auth.users(id)
        on delete cascade,

    display_name text,
    phone text,

    created_at timestamptz not null
        default timezone('utc', now()),

    updated_at timestamptz not null
        default timezone('utc', now())
);

create index user_profiles_display_name_idx
    on public.user_profiles(display_name);

alter table public.user_profiles enable row level security;


-- User can read their own profile.
create policy user_profiles_select_self
on public.user_profiles
for select
to authenticated
using (
    user_id = auth.uid()
);


-- User can create their own profile.
create policy user_profiles_insert_self
on public.user_profiles
for insert
to authenticated
with check (
    user_id = auth.uid()
);


-- User can update their own profile.
create policy user_profiles_update_self
on public.user_profiles
for update
to authenticated
using (
    user_id = auth.uid()
)
with check (
    user_id = auth.uid()
);


-- ============================================================================
-- 2. ORGANIZATION ROLE HELPERS
-- ============================================================================

create or replace function public.has_organization_role(
    target_organization_id uuid,
    allowed_roles public.organization_role[]
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (
        select 1
        from public.organization_members om
        where om.organization_id = target_organization_id
          and om.user_id = auth.uid()
          and om.status = 'active'
          and om.role = any(allowed_roles)
    );
$$;


create or replace function public.is_organization_admin(
    target_organization_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.has_organization_role(
        target_organization_id,
        array[
            'owner'::public.organization_role,
            'admin'::public.organization_role
        ]
    );
$$;


create or replace function public.is_organization_reviewer(
    target_organization_id uuid
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.has_organization_role(
        target_organization_id,
        array[
            'owner'::public.organization_role,
            'admin'::public.organization_role,
            'reviewer'::public.organization_role
        ]
    );
$$;


-- ============================================================================
-- 3. ORGANIZATION LOCATIONS
-- ============================================================================

create type public.organization_location_type as enum (
    'primary',
    'mailing',
    'operating',
    'registered'
);


create table public.organization_locations (
    id uuid primary key default gen_random_uuid(),

    organization_id uuid not null
        references public.organizations(id)
        on delete cascade,

    location_type public.organization_location_type not null,

    address_line_1 text not null,
    address_line_2 text,

    city text not null,
    state text,
    postal_code text,
    country text not null default 'US',

    is_primary boolean not null default false,

    created_at timestamptz not null
        default timezone('utc', now()),

    updated_at timestamptz not null
        default timezone('utc', now())
);

create index organization_locations_organization_id_idx
    on public.organization_locations(organization_id);

create index organization_locations_type_idx
    on public.organization_locations(location_type);

create index organization_locations_primary_idx
    on public.organization_locations(
        organization_id,
        is_primary
    );


alter table public.organization_locations enable row level security;


create policy organization_locations_select_member
on public.organization_locations
for select
to authenticated
using (
    public.is_organization_member(organization_id)
);


create policy organization_locations_insert_admin
on public.organization_locations
for insert
to authenticated
with check (
    public.is_organization_admin(organization_id)
);


create policy organization_locations_update_admin
on public.organization_locations
for update
to authenticated
using (
    public.is_organization_admin(organization_id)
)
with check (
    public.is_organization_admin(organization_id)
);


create policy organization_locations_delete_admin
on public.organization_locations
for delete
to authenticated
using (
    public.is_organization_admin(organization_id)
);


-- ============================================================================
-- 4. UPDATED_AT TRIGGER FOR USER PROFILES
-- ============================================================================

create trigger user_profiles_set_updated_at
before update on public.user_profiles
for each row
execute function public.set_updated_at();


create trigger organization_locations_set_updated_at
before update on public.organization_locations
for each row
execute function public.set_updated_at();


-- ============================================================================
-- 5. VERIFICATION ITEM HISTORY
--
-- This is different from audit_logs.
--
-- audit_logs:
--     Who performed an application action?
--
-- verification_item_history:
--     How did a verification item's state evolve?
--
-- History is append-only.
-- ============================================================================

create type public.verification_history_action as enum (
    'created',
    'status_changed',
    'review_started',
    'approved',
    'rejected',
    'correction_requested',
    'verification_requested',
    'verification_completed',
    'note_added'
);


create table public.verification_item_history (
    id uuid primary key default gen_random_uuid(),

    verification_item_id uuid not null
        references public.verification_items(id)
        on delete cascade,

    previous_status public.verification_item_status,

    new_status public.verification_item_status,

    action public.verification_history_action not null,

    reason text,

    notes text,

    actor_user_id uuid
        references auth.users(id)
        on delete set null,

    created_at timestamptz not null
        default timezone('utc', now())
);

create index verification_item_history_item_idx
    on public.verification_item_history(
        verification_item_id,
        created_at desc
    );

create index verification_item_history_actor_idx
    on public.verification_item_history(actor_user_id);

create index verification_item_history_created_at_idx
    on public.verification_item_history(created_at desc);


alter table public.verification_item_history enable row level security;


create policy verification_item_history_select_member
on public.verification_item_history
for select
to authenticated
using (
    exists (
        select 1
        from public.verification_items vi
        join public.verification_cases vc
            on vc.id = vi.verification_case_id
        where vi.id = verification_item_history.verification_item_id
          and public.is_organization_member(vc.organization_id)
    )
);


-- No INSERT/UPDATE/DELETE policy is intentionally exposed to
-- normal authenticated users.
--
-- History should be created by controlled backend operations.


-- ============================================================================
-- 6. DOCUMENT ↔ VERIFICATION ITEM RELATIONSHIP
--
-- Allows us to explicitly say:
--
--   EIN verification item
--       -> EIN document
--
-- rather than relying only on document_type.
-- ============================================================================

create table public.verification_item_documents (
    verification_item_id uuid not null
        references public.verification_items(id)
        on delete cascade,

    document_id uuid not null
        references public.documents(id)
        on delete cascade,

    created_at timestamptz not null
        default timezone('utc', now()),

    primary key (
        verification_item_id,
        document_id
    )
);

create index verification_item_documents_document_idx
    on public.verification_item_documents(document_id);


alter table public.verification_item_documents enable row level security;


create policy verification_item_documents_select_member
on public.verification_item_documents
for select
to authenticated
using (
    exists (
        select 1
        from public.verification_items vi
        join public.verification_cases vc
            on vc.id = vi.verification_case_id
        where vi.id = verification_item_documents.verification_item_id
          and public.is_organization_member(vc.organization_id)
    )
);


create policy verification_item_documents_insert_member
on public.verification_item_documents
for insert
to authenticated
with check (
    exists (
        select 1
        from public.verification_items vi
        join public.verification_cases vc
            on vc.id = vi.verification_case_id
        where vi.id = verification_item_documents.verification_item_id
          and public.is_organization_member(vc.organization_id)
    )
    and
    exists (
        select 1
        from public.documents d
        where d.id = verification_item_documents.document_id
          and public.is_organization_member(d.organization_id)
    )
);


create policy verification_item_documents_delete_admin
on public.verification_item_documents
for delete
to authenticated
using (
    exists (
        select 1
        from public.verification_items vi
        join public.verification_cases vc
            on vc.id = vi.verification_case_id
        where vi.id = verification_item_documents.verification_item_id
          and public.is_organization_admin(vc.organization_id)
    )
);


-- ============================================================================
-- 7. HARDEN BUSINESS UPDATE PERMISSIONS
--
-- Previously:
--     any active member could update businesses.
--
-- Now:
--     owner/admin can update business records.
--
-- Members can still read businesses.
-- ============================================================================

drop policy if exists businesses_update_member
on public.businesses;


create policy businesses_update_admin
on public.businesses
for update
to authenticated
using (
    public.is_organization_admin(organization_id)
)
with check (
    public.is_organization_admin(organization_id)
);


-- ============================================================================
-- 8. HARDEN VERIFICATION CASE UPDATE PERMISSIONS
--
-- Members can create cases.
-- Only owner/admin/reviewer can modify workflow state.
-- ============================================================================

drop policy if exists verification_cases_update_member
on public.verification_cases;


create policy verification_cases_update_reviewer
on public.verification_cases
for update
to authenticated
using (
    public.is_organization_reviewer(organization_id)
)
with check (
    public.is_organization_reviewer(organization_id)
);


-- ============================================================================
-- 9. VERIFICATION ITEM UPDATE PERMISSION
--
-- Previously there was no update policy.
--
-- Explicitly allow reviewers to update verification workflow data.
-- ============================================================================

create policy verification_items_update_reviewer
on public.verification_items
for update
to authenticated
using (
    exists (
        select 1
        from public.verification_cases vc
        where vc.id = verification_items.verification_case_id
          and public.is_organization_reviewer(vc.organization_id)
    )
)
with check (
    exists (
        select 1
        from public.verification_cases vc
        where vc.id = verification_items.verification_case_id
          and public.is_organization_reviewer(vc.organization_id)
    )
);


-- ============================================================================
-- 10. DOCUMENT REVIEW PERMISSION
--
-- Members may upload documents.
-- Review decisions belong to reviewers/admins.
-- ============================================================================

create policy documents_update_reviewer
on public.documents
for update
to authenticated
using (
    public.is_organization_reviewer(organization_id)
)
with check (
    public.is_organization_reviewer(organization_id)
);


-- ============================================================================
-- 11. PREVENT NORMAL USERS FROM DELETING VERIFICATION HISTORY
--
-- No policy is created.
-- ============================================================================


-- ============================================================================
-- 12. COMMENTS / DOCUMENTATION
-- ============================================================================

comment on table public.user_profiles is
    'Application-level user profile linked one-to-one with auth.users.';

comment on table public.organization_locations is
    'Normalized organization address/location records.';

comment on table public.verification_item_history is
    'Append-only verification workflow history.';

comment on table public.verification_item_documents is
    'Explicit relationship between verification requirements and supporting documents.';

comment on function public.has_organization_role(uuid, public.organization_role[]) is
    'Returns true when the current authenticated user has one of the specified active organization roles.';

comment on function public.is_organization_admin(uuid) is
    'Returns true for active organization owner/admin members.';

comment on function public.is_organization_reviewer(uuid) is
    'Returns true for active organization owner/admin/reviewer members.';


-- ============================================================================
-- END MILESTONE 2
-- ============================================================================