import { createClient, SupabaseClient } from '@supabase/supabase-js';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

/**
 * Client-side Supabase instance (anon key, respects RLS)
 * Use for browser-side reads
 */
export function getSupabaseClient(): SupabaseClient {
  return createClient(supabaseUrl, supabaseAnonKey);
}

/**
 * Server-side Supabase instance (service role key, bypasses RLS)
 * Use ONLY in server actions, API routes, and server components
 */
export function getSupabaseAdmin(): SupabaseClient {
  if (!supabaseServiceKey) {
    throw new Error('SUPABASE_SERVICE_ROLE_KEY is not configured');
  }
  return createClient(supabaseUrl, supabaseServiceKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });
}

/**
 * Singleton instances for reuse within the same request
 */
let _client: SupabaseClient | null = null;
let _admin: SupabaseClient | null = null;

export function supabaseClient(): SupabaseClient {
  if (!_client) {
    _client = getSupabaseClient();
  }
  return _client;
}

export function supabaseAdmin(): SupabaseClient {
  if (!_admin) {
    _admin = getSupabaseAdmin();
  }
  return _admin;
}
