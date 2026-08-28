-- Online Learning Platform - initial Supabase schema
-- Run this once in Supabase SQL Editor.
-- Public sign-up can create only student or teacher roles. Admin is NEVER assigned from the browser.

create type public.user_role as enum ('student','teacher','admin');
create type public.lesson_status as enum ('scheduled','live','completed','cancelled');
create type public.assignment_status as enum ('assigned','submitted','reviewed','completed');

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role public.user_role not null default 'student',
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.lessons (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references public.profiles(id) on delete cascade,
  student_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  start_at timestamptz not null,
  end_at timestamptz,
  status public.lesson_status not null default 'scheduled',
  room_code text unique,
  created_at timestamptz not null default now()
);

create table public.assignments (
  id uuid primary key default gen_random_uuid(),
  teacher_id uuid not null references public.profiles(id) on delete cascade,
  student_id uuid not null references public.profiles(id) on delete cascade,
  lesson_id uuid references public.lessons(id) on delete set null,
  title text not null,
  description text,
  due_at timestamptz,
  status public.assignment_status not null default 'assigned',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Create a profile automatically after auth sign-up.
-- The browser may request only student or teacher; any other value becomes student.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  requested text;
  safe_role public.user_role;
begin
  requested := coalesce(new.raw_user_meta_data->>'requested_role','student');
  safe_role := case when requested = 'teacher' then 'teacher'::public.user_role else 'student'::public.user_role end;
  insert into public.profiles (id, full_name, role)
  values (new.id, new.raw_user_meta_data->>'full_name', safe_role);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_admin()
returns boolean
language sql
stable
security definer set search_path = public
as $$
  select exists(select 1 from public.profiles where id = auth.uid() and role = 'admin' and active = true);
$$;

alter table public.profiles enable row level security;
alter table public.lessons enable row level security;
alter table public.assignments enable row level security;

-- Profiles
create policy "profile own read" on public.profiles for select using (id = auth.uid());
create policy "admin profiles read" on public.profiles for select using (public.is_admin());
create policy "profile own update" on public.profiles for update using (id = auth.uid()) with check (id = auth.uid());
create policy "admin profiles update" on public.profiles for update using (public.is_admin()) with check (public.is_admin());

-- Lessons: only participants or admin can read.
create policy "lesson participants read" on public.lessons for select using (teacher_id = auth.uid() or student_id = auth.uid() or public.is_admin());
create policy "teacher lessons insert" on public.lessons for insert with check (teacher_id = auth.uid() or public.is_admin());
create policy "teacher lessons update" on public.lessons for update using (teacher_id = auth.uid() or public.is_admin()) with check (teacher_id = auth.uid() or public.is_admin());
create policy "admin lessons delete" on public.lessons for delete using (public.is_admin());

-- Assignments: only the assigned student, teacher, or admin can read.
create policy "assignment participants read" on public.assignments for select using (teacher_id = auth.uid() or student_id = auth.uid() or public.is_admin());
create policy "teacher assignments insert" on public.assignments for insert with check (teacher_id = auth.uid() or public.is_admin());
create policy "assignment participants update" on public.assignments for update using (teacher_id = auth.uid() or student_id = auth.uid() or public.is_admin()) with check (teacher_id = auth.uid() or student_id = auth.uid() or public.is_admin());
create policy "admin assignments delete" on public.assignments for delete using (public.is_admin());

-- Helpful indexes
create index lessons_teacher_start_idx on public.lessons(teacher_id,start_at);
create index lessons_student_start_idx on public.lessons(student_id,start_at);
create index assignments_teacher_status_idx on public.assignments(teacher_id,status);
create index assignments_student_status_idx on public.assignments(student_id,status);

-- AFTER creating the two real users through Auth, promote ONLY those accounts manually:
-- update public.profiles set role='admin' where id=(select id from auth.users where email='FIRST_ADMIN_EMAIL');
-- update public.profiles set role='admin' where id=(select id from auth.users where email='SECOND_ADMIN_EMAIL');
