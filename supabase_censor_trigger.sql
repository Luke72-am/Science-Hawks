-- Server-side (database-side) profanity filter for reviews, so it can't be
-- bypassed by calling the API directly with unfiltered text.
create or replace function public.censor_review()
returns trigger
language plpgsql
as $$
declare
  bad_words text[] := array['fuck','shit','bitch','asshole','bastard','dick','piss','cunt','cock','pussy','slut','whore','damn','crap','hell'];
  word text;
begin
  foreach word in array bad_words loop
    new.text := regexp_replace(new.text, '\y' || word || '\y', repeat('*', length(word)), 'gi');
  end loop;
  return new;
end;
$$;

create trigger censor_review_before_insert
  before insert on public.reviews
  for each row execute procedure public.censor_review();
