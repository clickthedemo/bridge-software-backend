-- ============================================================================
-- BRIDGE — Initial Database Schema
-- Migration: 20260812100539_initial_schema
-- ============================================================================

create extension if not exists pgcrypto;

-- ============================================================================
-- ENUMS
-- ============================================================================

create type public.organization_status as enum (
    'active',
    'suspended',
    'archived'
);

create type public.membership_status as enum (
    'active',
    'invited',
    'suspended',
    'removed'
);

create type public.organization_role as enum (
    'owner',
    'admin',
    'reviewer',
    'member'
);

create type public.business_status as enum (
    'active',
    'inactive',
    'archived'
);

create type public.verification_case_status as enum (
    'draft',
    'submitted',
    'in_review',
    'action_required',
    'approved',
    'rejected',
    'cancelled'
);

create type public.verification_item_type as enum (
    'ein',
    'cannabis_license',
    'business_registration',
    'document'
);

create type public.verification_item_status as enum (
    'pending',
    'in_review',
    'verification_requested',
    'verified',
    'rejected',
    'correction_required',
    'not_applicable'
);

create type public.verification_method as enum (
    'manual',
    'api'
);

create type public.document_type as enum (
    'ein',
    'cannabis_license',
    'business_registration',
    'other'
);

create type public.document_review_status as enum (
    'pending',
    'approved',
    'rejected',
    'correction_required'
);

create type public.audit_action as enum (
    'create',
    'update',
    'delete',
    'submit',
    'review',
    'approve',
    'reject',
    'request_correction',
    'verification_requested',
    'verification_completed'
);

-- ============================================================================
-- COMMON FUNCTIONS
-- ============================================================================

create or replace function public.set_updated_at()
returns trigger
language plpgsql
security invoker
set search_path = public
as $$
begin
    new.updated_at = timezone('utc', now());
    return new;
end;
$$;

-- ============================================================================
-- ORGANIZATIONS
-- ============================================================================

create table public.organizations (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    status public.organization_status not null default 'active',
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now())
);

create index organizations_status_idx
    on public.organizations(status);

-- ============================================================================
-- ORGANIZATION MEMBERS
-- ============================================================================

create table public.organization_members (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id)
        on delete cascade,
    user_id uuid not null
        references auth.users(id)
        on delete cascade,
    role public.organization_role not null default 'member',
    status public.membership_status not null default 'active',
    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),

    constraint organization_members_organization_user_unique
        unique (organization_id, user_id)
);

create index organization_members_user_id_idx
    on public.organization_members(user_id);

create index organization_members_organization_id_idx
    on public.organization_members(organization_id);

create index organization_members_status_idx
    on public.organization_members(status);

-- ============================================================================
-- BUSINESSES
-- ============================================================================

create table public.businesses (
    id uuid primary key default gen_random_uuid(),
    organization_id uuid not null
        references public.organizations(id)
        on delete restrict,

    legal_name text not null,
    dba_name text,
    status public.business_status not null default 'active',

    ein_last_four text,
    cannabis_license_number text,
    cannabis_license_state text,

    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),

    constraint businesses_ein_last_four_format
        check (
            ein_last_four is null
            or ein_last_four ~ '^[0-9]{4}$'
        ),

    constraint businesses_license_state_format
        check (
            cannabis_license_state is null
            or cannabis_license_state ~ '^[A-Z]{2}$'
        )
);

create index businesses_organization_id_idx
    on public.businesses(organization_id);

create index businesses_status_idx
    on public.businesses(status);

create index businesses_legal_name_idx
    on public.businesses(legal_name);

-- ============================================================================
-- VERIFICATION CASES
-- ============================================================================

create table public.verification_cases (
    id uuid primary key default gen_random_uuid(),

    organization_id uuid not null
        references public.organizations(id)
        on delete restrict,

    business_id uuid not null
        references public.businesses(id)
        on delete restrict,

    status public.verification_case_status not null default 'draft',

    submitted_at timestamptz,
    started_review_at timestamptz,
    completed_at timestamptz,

    assigned_admin_user_id uuid
        references auth.users(id)
        on delete set null,

    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),

    constraint verification_cases_completed_at_status_check
        check (
            status not in ('approved', 'rejected')
            or completed_at is not null
        )
);

create index verification_cases_organization_id_idx
    on public.verification_cases(organization_id);

create index verification_cases_business_id_idx
    on public.verification_cases(business_id);

create index verification_cases_status_idx
    on public.verification_cases(status);

create index verification_cases_assigned_admin_idx
    on public.verification_cases(assigned_admin_user_id);

-- ============================================================================
-- VERIFICATION ITEMS
-- ============================================================================

create table public.verification_items (
    id uuid primary key default gen_random_uuid(),

    verification_case_id uuid not null
        references public.verification_cases(id)
        on delete cascade,

    item_type public.verification_item_type not null,

    status public.verification_item_status not null default 'pending',

    verification_method public.verification_method,

    reviewed_by_user_id uuid
        references auth.users(id)
        on delete set null,

    reviewed_at timestamptz,

    rejection_reason text,
    correction_notes text,

    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),

    constraint verification_items_case_type_unique
        unique (verification_case_id, item_type)
);

create index verification_items_case_id_idx
    on public.verification_items(verification_case_id);

create index verification_items_status_idx
    on public.verification_items(status);

-- ============================================================================
-- EIN VERIFICATION
--
-- IMPORTANT:
-- The API verification is ADMIN-TRIGGERED.
-- It is not automatically executed when a case is submitted.
-- ============================================================================

create table public.ein_verifications (
    id uuid primary key default gen_random_uuid(),

    verification_item_id uuid not null
        references public.verification_items(id)
        on delete cascade,

    provider text not null,
    provider_reference text,

    requested_by_user_id uuid not null
        references auth.users(id)
        on delete restrict,

    requested_at timestamptz not null default timezone('utc', now()),
    completed_at timestamptz,

    result_status text,
    result_reason text,

    provider_response jsonb,

    created_at timestamptz not null default timezone('utc', now()),

    constraint ein_verifications_item_unique
        unique (verification_item_id, id)
);

create index ein_verifications_item_idx
    on public.ein_verifications(verification_item_id);

create index ein_verifications_provider_reference_idx
    on public.ein_verifications(provider_reference);

-- ============================================================================
-- CANNABIS LICENSE VERIFICATION
--
-- MVP:
-- Manual lookup by admin against the relevant state registry.
--
-- Automated registry API integrations are intentionally NOT modeled
-- as a requirement for the MVP.
-- ============================================================================

create table public.cannabis_license_verifications (
    id uuid primary key default gen_random_uuid(),

    verification_item_id uuid not null
        references public.verification_items(id)
        on delete cascade,

    state_code text not null,

    license_number text not null,

    registry_name text,

    registry_url text,

    looked_up_by_user_id uuid not null
        references auth.users(id)
        on delete restrict,

    looked_up_at timestamptz not null default timezone('utc', now()),

    result_status text,
    result_notes text,

    created_at timestamptz not null default timezone('utc', now()),

    constraint cannabis_license_state_format
        check (state_code ~ '^[A-Z]{2}$')
);

create index cannabis_license_verifications_item_idx
    on public.cannabis_license_verifications(verification_item_id);

create index cannabis_license_verifications_license_idx
    on public.cannabis_license_verifications(state_code, license_number);

-- ============================================================================
-- DOCUMENTS
--
-- Documents themselves are ALWAYS manually reviewed.
-- An underlying data point may have a separate API verification,
-- but the uploaded document remains subject to admin review.
-- ============================================================================

create table public.documents (
    id uuid primary key default gen_random_uuid(),

    organization_id uuid not null
        references public.organizations(id)
        on delete restrict,

    business_id uuid not null
        references public.businesses(id)
        on delete restrict,

    verification_case_id uuid not null
        references public.verification_cases(id)
        on delete cascade,

    document_type public.document_type not null,

    file_name text not null,
    storage_bucket text not null,
    storage_path text not null,

    mime_type text,
    file_size_bytes bigint,

    uploaded_by_user_id uuid not null
        references auth.users(id)
        on delete restrict,

    uploaded_at timestamptz not null default timezone('utc', now()),

    review_status public.document_review_status not null default 'pending',

    reviewed_by_user_id uuid
        references auth.users(id)
        on delete set null,

    reviewed_at timestamptz,

    review_notes text,

    created_at timestamptz not null default timezone('utc', now()),
    updated_at timestamptz not null default timezone('utc', now()),

    constraint documents_file_size_positive
        check (
            file_size_bytes is null
            or file_size_bytes > 0
        )
);

create index documents_organization_id_idx
    on public.documents(organization_id);

create index documents_business_id_idx
    on public.documents(business_id);

create index documents_verification_case_id_idx
    on public.documents(verification_case_id);

create index documents_review_status_idx
    on public.documents(review_status);

-- ============================================================================
-- AUDIT LOG
-- ============================================================================

create table public.audit_logs (
    id uuid primary key default gen_random_uuid(),

    organization_id uuid
        references public.organizations(id)
        on delete set null,

    actor_user_id uuid
        references auth.users(id)
        on delete set null,

    action public.audit_action not null,

    entity_type text not null,
    entity_id uuid,

    metadata jsonb,

    created_at timestamptz not null default timezone('utc', now())
);

create index audit_logs_organization_id_idx
    on public.audit_logs(organization_id);

create index audit_logs_actor_user_id_idx
    on public.audit_logs(actor_user_id);

create index audit_logs_entity_idx
    on public.audit_logs(entity_type, entity_id);

create index audit_logs_created_at_idx
    on public.audit_logs(created_at desc);

-- ============================================================================
-- UPDATED_AT TRIGGERS
-- ============================================================================

create trigger organizations_set_updated_at
before update on public.organizations
for each row
execute function public.set_updated_at();

create trigger organization_members_set_updated_at
before update on public.organization_members
for each row
execute function public.set_updated_at();

create trigger businesses_set_updated_at
before update on public.businesses
for each row
execute function public.set_updated_at();

create trigger verification_cases_set_updated_at
before update on public.verification_cases
for each row
execute function public.set_updated_at();

create trigger verification_items_set_updated_at
before update on public.verification_items
for each row
execute function public.set_updated_at();

create trigger documents_set_updated_at
before update on public.documents
for each row
execute function public.set_updated_at();

-- ============================================================================
-- ROW LEVEL SECURITY
-- ============================================================================

alter table public.organizations enable row level security;
alter table public.organization_members enable row level security;
alter table public.businesses enable row level security;
alter table public.verification_cases enable row level security;
alter table public.verification_items enable row level security;
alter table public.ein_verifications enable row level security;
alter table public.cannabis_license_verifications enable row level security;
alter table public.documents enable row level security;
alter table public.audit_logs enable row level security;

-- ============================================================================
-- MEMBERSHIP HELPER
-- ============================================================================

create or replace function public.is_organization_member(
    target_organization_id uuid
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
    );
$$;

-- ============================================================================
-- ORGANIZATION POLICIES
-- ============================================================================

create policy organizations_select_member
on public.organizations
for select
to authenticated
using (
    public.is_organization_member(id)
);

-- ============================================================================
-- ORGANIZATION MEMBERS POLICIES
-- ============================================================================

create policy organization_members_select_member
on public.organization_members
for select
to authenticated
using (
    public.is_organization_member(organization_id)
);

-- ============================================================================
-- BUSINESS POLICIES
-- ============================================================================

create policy businesses_select_member
on public.businesses
for select
to authenticated
using (
    public.is_organization_member(organization_id)
);

create policy businesses_insert_member
on public.businesses
for insert
to authenticated
with check (
    public.is_organization_member(organization_id)
);

create policy businesses_update_member
on public.businesses
for update
to authenticated
using (
    public.is_organization_member(organization_id)
)
with check (
    public.is_organization_member(organization_id)
);

-- ============================================================================
-- VERIFICATION CASE POLICIES
-- ============================================================================

create policy verification_cases_select_member
on public.verification_cases
for select
to authenticated
using (
    public.is_organization_member(organization_id)
);

create policy verification_cases_insert_member
on public.verification_cases
for insert
to authenticated
with check (
    public.is_organization_member(organization_id)
);

create policy verification_cases_update_member
on public.verification_cases
for update
to authenticated
using (
    public.is_organization_member(organization_id)
)
with check (
    public.is_organization_member(organization_id)
);

-- ============================================================================
-- VERIFICATION ITEM POLICIES
-- ============================================================================

create policy verification_items_select_member
on public.verification_items
for select
to authenticated
using (
    exists (
        select 1
        from public.verification_cases vc
        where vc.id = verification_items.verification_case_id
          and public.is_organization_member(vc.organization_id)
    )
);

-- ============================================================================
-- DOCUMENT POLICIES
-- ============================================================================

create policy documents_select_member
on public.documents
for select
to authenticated
using (
    public.is_organization_member(organization_id)
);

create policy documents_insert_member
on public.documents
for insert
to authenticated
with check (
    public.is_organization_member(organization_id)
);

-- ============================================================================
-- AUDIT LOG POLICIES
--
-- Audit records are intentionally read-only for authenticated users.
-- Application/service code should create audit records through controlled
-- backend operations.
-- ============================================================================

create policy audit_logs_select_member
on public.audit_logs
for select
to authenticated
using (
    organization_id is not null
    and public.is_organization_member(organization_id)
);

-- ============================================================================
-- END
-- ============================================================================