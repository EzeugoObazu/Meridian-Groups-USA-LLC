create table public.naics_codes (
  code text primary key check (code ~ '^[0-9]{6}$'),
  title text not null check (char_length(title) between 3 and 300),
  division text not null default '' check (char_length(division) <= 200),
  published boolean not null default true,
  sam_confirmed boolean not null default false,
  sort int not null default 0,
  updated_at timestamptz not null default now()
);
grant select on public.naics_codes to anon, authenticated;
grant insert, update, delete on public.naics_codes to authenticated;
grant all on public.naics_codes to service_role;
alter table public.naics_codes enable row level security;
create policy "Public sees published" on public.naics_codes for select to anon, authenticated using (published or public.is_staff(auth.uid()));
create policy "Admins manage" on public.naics_codes for all to authenticated using (public.is_admin(auth.uid())) with check (public.is_admin(auth.uid()));

insert into public.naics_codes (code, title, division, published, sort) values
 ('541611','Administrative Management and General Management Consulting Services','Program & Project Management; Administrative & Business Support', true, 1),
 ('541614','Process, Physical Distribution, and Logistics Consulting Services','Logistics & Supply Chain Solutions', true, 2),
 ('541512','Computer Systems Design Services','Information Technology & Digital Solutions', true, 3),
 ('541519','Other Computer Related Services','Information Technology & Digital Solutions', true, 4),
 ('541618','Other Management Consulting Services','Strategic Procurement & Contracting; Program & Project Management', true, 5),
 ('561110','Office Administrative Services','Administrative & Business Support', true, 6),
 ('541511','Custom Computer Programming Services','Information Technology & Digital Solutions (pending confirmation)', false, 7);

insert into public.company_fields (key, label, category, sort) values ('primary_naics','Primary NAICS Code','codes',4) on conflict do nothing;