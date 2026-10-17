import createClient from 'openapi-fetch';
import type { paths } from './schema';
export const api = createClient<paths>();

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch('/api/v1' + path, init);
  if (!response.ok) {
    if (response.status === 401) throw new Error('Sign in to continue.');
    throw new Error(`Request failed (${response.status}).`);
  }
  return response.json();
}
export type Resource = { id: string; name?: string; status?: string; severity?: string; acknowledged?: boolean; acknowledged_at?: string | null };
export type List<T> = { items: T[]; next?: string | null };
export async function list<T>(path: string): Promise<T[]> {
  const items: T[] = [];
  const seen = new Set<string>();
  let cursor: string | undefined;
  do {
    const params = new URLSearchParams({ limit: '200' });
    if (cursor) params.set('cursor', cursor);
    const page = await request<List<T>>(path + '?' + params);
    items.push(...page.items);
    cursor = page.next ?? undefined;
    if (cursor && seen.has(cursor)) throw new Error('Invalid pagination cursor.');
    if (cursor) seen.add(cursor);
  } while (cursor);
  return items;
}
