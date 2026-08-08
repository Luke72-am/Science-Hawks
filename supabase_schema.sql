-- Science Hound: database schema, RLS policies, and admin auto-detection.
-- Run this once in the Supabase SQL Editor.

-- ---------- Tables ----------
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  is_admin boolean not null default false,
  blocked boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.videos (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  storage_path text not null,
  uploaded_at timestamptz not null default now(),
  release_days int[] not null default '{}',
  release_date date  -- null = publishes immediately; else the first qualifying weekday, computed client-side at upload
);

create table public.reviews (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  username text not null,
  text text not null,
  created_at timestamptz not null default now()
);

create table public.site_settings (
  key text primary key,
  value text
);

insert into public.site_settings (key, value) values ('intro_text',
'Hello, my name is Luke, and I have created this website to support the local community and provide free education for children, especially homeschoolers. This website provides free access to 30 minute videos, created by yours truly, of science, STEM, space and physics. All of my information comes directly from these PUBLIC DOMAIN TEXTBOOKS (enter names here). Every Tuesday and Thursday I release my videos, for you to watch and have complete access to forever.

Every Tuesday I release a video covering chemistry and STEM related topics. First we will cover the bonds between atoms and molecules, how they all work. Then we will cover different kinds of popular chemical compounds and bonds, and their uses in later videos. Thursdays I release space and physics related videos. We will cover astronomy, how stars and black holes work, the true scale of the universe, and much more. Now I have much more content on chemistry though, and once I run out of space like content after a few months, maybe more, I will start covering chemistry in ALL released videos after that.

Now keep in mind I am not qualified or certified for this, I am only a teen. But my sources are very reliable and these topics are my passion. Lastly, this is a strictly CLEAN, and Christian site, no language or inappropriate content, this website is meant to serve the community, and The Lord. If you have any questions, comments or concerns, watch the video below. Or you can reach me at Travelingtreasures12345@gmail.com, or you can leave a review highlighting your thoughts. Thank you God be with you all.');

insert into public.site_settings (key, value) values ('intro_video_path', null);

-- ---------- Auto-create a profile row on signup; the reserved admin username becomes admin automatically ----------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  chosen_username text;
begin
  chosen_username := coalesce(new.raw_user_meta_data->>'username', split_part(new.email, '@', 1));
  insert into public.profiles (id, username, is_admin)
  values (new.id, chosen_username, (lower(chosen_username) = 'luke'));
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- ---------- Helper: is the current requester an admin? ----------
create or replace function public.is_admin()
returns boolean
language sql
security definer
set search_path = public
as $$
  select coalesce((select is_admin from public.profiles where id = auth.uid()), false);
$$;

create or replace function public.is_blocked(uid uuid)
returns boolean
language sql
security definer
set search_path = public
as $$
  select coalesce((select blocked from public.profiles where id = uid), false);
$$;

-- ---------- Row Level Security ----------
alter table public.profiles enable row level security;
alter table public.videos enable row level security;
alter table public.reviews enable row level security;
alter table public.site_settings enable row level security;

create policy "profiles viewable by everyone" on public.profiles
  for select using (true);
create policy "admin can update any profile" on public.profiles
  for update using (public.is_admin());

create policy "released videos viewable by everyone, all videos viewable by admin" on public.videos
  for select using (
    public.is_admin() or release_date is null or release_date <= current_date
  );
create policy "only admin can insert videos" on public.videos
  for insert with check (public.is_admin());
create policy "only admin can delete unreleased videos" on public.videos
  for delete using (public.is_admin() and release_date is not null and release_date > current_date);
create policy "only admin can update videos" on public.videos
  for update using (public.is_admin());

create policy "reviews viewable by everyone" on public.reviews
  for select using (true);
create policy "signed in non-blocked users can post reviews" on public.reviews
  for insert with check (auth.uid() = user_id and not public.is_blocked(auth.uid()));
create policy "owner or admin can delete review" on public.reviews
  for delete using (auth.uid() = user_id or public.is_admin());

create policy "settings viewable by everyone" on public.site_settings
  for select using (true);
create policy "only admin can change settings" on public.site_settings
  for update using (public.is_admin());
create policy "only admin can insert settings" on public.site_settings
  for insert with check (public.is_admin());
