create extension if not exists pgcrypto;

create table if not exists public.senders (
    id uuid primary key default gen_random_uuid(),
    name text not null,
    email text not null,
    provider text not null check (provider in ('cloudflare', 'resend')),
    credential text not null,
    account_id text,
    reply_to text,
    status text not null default 'active'
        check (status in ('active', 'dead')),
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

alter table public.senders enable row level security;

alter table public.senders
    add column if not exists reply_to text;

update public.senders
set reply_to = email
where reply_to is null or trim(reply_to) = '';

create index if not exists senders_status_idx
    on public.senders(status);

create index if not exists senders_created_at_idx
    on public.senders(created_at);
