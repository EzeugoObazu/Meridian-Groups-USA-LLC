
create type public.app_role as enum ('super_admin','admin','proposal_manager','compliance_reviewer','bd_user','read_only');

create table public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade not null,
  role app_role not null,
  created_at timestamptz not null default now(),
  unique (user_id, role)
);
grant select on public.user_roles to authenticated;
grant all on public.user_roles to service_role;
alter table public.user_roles enable row level security;

create or replace function public.has_role(_user_id uuid, _role app_role)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role = _role)
$$;
create or replace function public.is_staff(_user_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id)
$$;
create or replace function public.can_edit(_user_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role <> 'read_only')
$$;
create or replace function public.is_admin(_user_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.user_roles where user_id = _user_id and role in ('super_admin','admin'))
$$;

create policy "Users see own roles; admins see all" on public.user_roles for select to authenticated
  using (user_id = auth.uid() or public.is_admin(auth.uid()));

-- First account to sign up becomes Super Administrator; later accounts get no access until an admin assigns a role.
create or replace function public.bootstrap_first_admin()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.user_roles where role = 'super_admin') then
    insert into public.user_roles (user_id, role) values (new.id, 'super_admin');
  end if;
  return new;
end $$;
create trigger on_auth_user_created_bootstrap after insert on auth.users
  for each row execute function public.bootstrap_first_admin();

-- Admin-only role management via function (prevents self-escalation through table writes)
create or replace function public.set_user_role(_user_id uuid, _role app_role, _grant boolean)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin(auth.uid()) then raise exception 'Forbidden'; end if;
  if _role = 'super_admin' and not public.has_role(auth.uid(),'super_admin') then raise exception 'Only a Super Administrator can grant that role'; end if;
  if _grant then insert into public.user_roles(user_id, role) values (_user_id, _role) on conflict do nothing;
  else delete from public.user_roles where user_id = _user_id and role = _role; end if;
  insert into public.audit_logs(actor_id, action, entity, entity_id, details)
    values (auth.uid(), case when _grant then 'grant_role' else 'revoke_role' end, 'user_roles', _user_id::text, jsonb_build_object('role', _role));
end $$;

create table public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid,
  action text not null,
  entity text not null,
  entity_id text,
  details jsonb,
  created_at timestamptz not null default now()
);
grant select, insert on public.audit_logs to authenticated;
grant all on public.audit_logs to service_role;
alter table public.audit_logs enable row level security;
create policy "Admins read audit" on public.audit_logs for select to authenticated using (public.is_admin(auth.uid()));
create policy "Staff write own audit" on public.audit_logs for insert to authenticated with check (public.is_staff(auth.uid()) and actor_id = auth.uid());

-- Public inquiries
create table public.contact_inquiries (
  id uuid primary key default gen_random_uuid(),
  full_name text not null check (char_length(full_name) between 2 and 100),
  organization text check (char_length(organization) <= 150),
  email text not null check (char_length(email) <= 255 and email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  phone text check (char_length(phone) <= 30),
  service_interest text check (char_length(service_interest) <= 100),
  message text not null check (char_length(message) between 10 and 4000),
  status text not null default 'new' check (status in ('new','in_progress','closed')),
  created_at timestamptz not null default now()
);
grant insert on public.contact_inquiries to anon, authenticated;
grant select, update, delete on public.contact_inquiries to authenticated;
grant all on public.contact_inquiries to service_role;
alter table public.contact_inquiries enable row level security;
create policy "Anyone can submit" on public.contact_inquiries for insert to anon, authenticated with check (status = 'new');
create policy "Staff read" on public.contact_inquiries for select to authenticated using (public.is_staff(auth.uid()));
create policy "Editors update" on public.contact_inquiries for update to authenticated using (public.can_edit(auth.uid()));
create policy "Admins delete" on public.contact_inquiries for delete to authenticated using (public.is_admin(auth.uid()));

create table public.partner_inquiries (
  id uuid primary key default gen_random_uuid(),
  company_name text not null check (char_length(company_name) between 2 and 150),
  contact_person text not null check (char_length(contact_person) between 2 and 100),
  email text not null check (char_length(email) <= 255 and email ~* '^[^@\s]+@[^@\s]+\.[^@\s]+$'),
  phone text check (char_length(phone) <= 30),
  business_category text check (char_length(business_category) <= 100),
  services_offered text check (char_length(services_offered) <= 1000),
  partnership_interest text check (char_length(partnership_interest) <= 100),
  message text not null check (char_length(message) between 10 and 4000),
  status text not null default 'new' check (status in ('new','reviewing','declined','follow_up')),
  created_at timestamptz not null default now()
);
grant insert on public.partner_inquiries to anon, authenticated;
grant select, update, delete on public.partner_inquiries to authenticated;
grant all on public.partner_inquiries to service_role;
alter table public.partner_inquiries enable row level security;
create policy "Anyone can submit" on public.partner_inquiries for insert to anon, authenticated with check (status = 'new');
create policy "Staff read" on public.partner_inquiries for select to authenticated using (public.is_staff(auth.uid()));
create policy "Editors update" on public.partner_inquiries for update to authenticated using (public.can_edit(auth.uid()));
create policy "Admins delete" on public.partner_inquiries for delete to authenticated using (public.is_admin(auth.uid()));

-- Company qualifications (public only when populated)
create table public.company_fields (
  key text primary key,
  label text not null,
  category text not null default 'registration',
  value text not null default '',
  sort int not null default 0,
  updated_at timestamptz not null default now(),
  updated_by uuid
);
grant select on public.company_fields to anon, authenticated;
grant insert, update, delete on public.company_fields to authenticated;
grant all on public.company_fields to service_role;
alter table public.company_fields enable row level security;
create policy "Public sees populated" on public.company_fields for select to anon, authenticated using (value <> '' or public.is_staff(auth.uid()));
create policy "Admins manage" on public.company_fields for all to authenticated using (public.is_admin(auth.uid())) with check (public.is_admin(auth.uid()));
insert into public.company_fields (key,label,category,sort) values
 ('uei','UEI','registration',1),('cage','CAGE Code','registration',2),('sam','SAM.gov Registration','registration',3),
 ('classifications','Business Classifications','registration',4),('naics','NAICS Codes','codes',5),('psc','PSC Codes','codes',6),
 ('certifications','Verified Certifications','qualifications',7),('vehicles','Contract Vehicles','qualifications',8),
 ('past_performance','Past Performance','qualifications',9),('capability_statement_url','Capability Statement (PDF link)','documents',10);

-- Contracting workspace (confidential)
create type public.solicitation_type as enum ('rfi','sources_sought','rfq','rfp','ifb','combined','amendment','other');
create table public.opportunities (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 2 and 300),
  solicitation_number text,
  type solicitation_type not null default 'rfp',
  agency text, contracting_office text, naics text, psc text, set_aside text,
  due_date timestamptz,
  status text not null default 'identified' check (status in ('identified','reviewing','bid','no_bid','in_proposal','submitted','awarded','lost')),
  contracting_officer text, source_url text, notes text,
  owner_id uuid,
  created_by uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
grant select, insert, update, delete on public.opportunities to authenticated;
grant all on public.opportunities to service_role;
alter table public.opportunities enable row level security;
create policy "Staff read" on public.opportunities for select to authenticated using (public.is_staff(auth.uid()));
create policy "Editors insert" on public.opportunities for insert to authenticated with check (public.can_edit(auth.uid()));
create policy "Editors update" on public.opportunities for update to authenticated using (public.can_edit(auth.uid()));
create policy "Admins delete" on public.opportunities for delete to authenticated using (public.is_admin(auth.uid()));

create table public.requirements (
  id uuid primary key default gen_random_uuid(),
  opportunity_id uuid not null references public.opportunities(id) on delete cascade,
  req_code text,
  description text not null,
  source_document text not null,
  source_location text not null,
  regulation text,
  required_action text,
  responsible_id uuid,
  evidence text,
  status text not null default 'open' check (status in ('open','in_progress','complete','not_applicable')),
  needs_human_review boolean not null default true,
  reviewer_approved boolean not null default false,
  mandatory boolean not null default true,
  created_at timestamptz not null default now()
);
grant select, insert, update, delete on public.requirements to authenticated;
grant all on public.requirements to service_role;
alter table public.requirements enable row level security;
create policy "Staff read" on public.requirements for select to authenticated using (public.is_staff(auth.uid()));
create policy "Editors insert" on public.requirements for insert to authenticated with check (public.can_edit(auth.uid()));
create policy "Editors update" on public.requirements for update to authenticated using (public.can_edit(auth.uid()));
create policy "Editors delete" on public.requirements for delete to authenticated using (public.can_edit(auth.uid()));

create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null check (char_length(title) between 2 and 300),
  due_date date,
  status text not null default 'todo' check (status in ('todo','in_progress','done')),
  assignee_id uuid,
  opportunity_id uuid references public.opportunities(id) on delete set null,
  created_by uuid,
  created_at timestamptz not null default now()
);
grant select, insert, update, delete on public.tasks to authenticated;
grant all on public.tasks to service_role;
alter table public.tasks enable row level security;
create policy "Staff read" on public.tasks for select to authenticated using (public.is_staff(auth.uid()));
create policy "Editors insert" on public.tasks for insert to authenticated with check (public.can_edit(auth.uid()));
create policy "Editors update" on public.tasks for update to authenticated using (public.can_edit(auth.uid()));
create policy "Editors delete" on public.tasks for delete to authenticated using (public.can_edit(auth.uid()));
