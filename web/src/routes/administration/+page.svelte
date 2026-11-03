<script lang="ts">
  import { onMount } from 'svelte';
  import { list, request } from '$lib/api/client';

  type Tenant = { id: string; name?: string; active?: boolean };
  let tenants: Tenant[] = [];
  let selected = '';
  let overview = '';
  let message = '';

  async function refresh() {
    try {
      tenants = await list<Tenant>('/tenants');
      selected = tenants.find((tenant) => tenant.active)?.id ?? '';
      try { overview = JSON.stringify(await request('/msp/overview')); }
      catch { overview = 'MSP overview is limited to owners and admins.'; }
    } catch (cause) { message = cause instanceof Error ? cause.message : 'Unable to load administration.'; }
  }
  onMount(() => { void refresh(); });

  async function switchTenant() {
    const tenantId = selected;
    if (!tenantId) return;
    try {
      const response = await fetch('/api/v1/session/tenant', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tenant_id: tenantId })
    });
      message = response.ok ? 'Tenant switched' : 'Switch refused. An MSP grant is required.';
    } catch { message = 'Unable to reach the server.'; }
    // Reload either way so the select reflects the session's actual tenant.
    await refresh();
  }
</script>

<h1 class="text-2xl">Administration</h1>
<p class="mt-2 text-[var(--muted)]">Users, tokens, media types and MSP grants. A grant is required before an operator can switch tenant.</p>
<label class="mt-4 block text-sm">Tenant
  <select class="mt-1 block border border-[var(--line)] bg-transparent px-2 py-1" bind:value={selected} on:change={switchTenant}>
    <option value="">Choose a tenant</option>
    {#each tenants as tenant}
      <option value={tenant.id}>{tenant.name ?? tenant.id}{tenant.active ? ' (current)' : ''}</option>
    {/each}
  </select>
</label>
{#if message}<p class="mt-3">{message}</p>{/if}
<pre class="mt-4 whitespace-pre-wrap text-sm">{overview}</pre>
