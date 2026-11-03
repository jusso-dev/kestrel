<script lang="ts">
  import { goto } from '$app/navigation';
  import { api } from '$lib/api/client';
  type Tenant = { id: string; name: string };
  let email = '';
  let password = '';
  let tenant = '';
  let tenants: Tenant[] = [];
  let message = '';
  let pending = false;

  async function submit() {
    if (pending) return;
    pending = true;
    message = '';
    try {
      const chosen = tenant.trim();
      const body = chosen ? { email, password, tenant: chosen } : { email, password };
      const { response, error } = await api.POST('/api/v1/login', { body });
      if (response.ok) {
        await goto('/');
        return;
      }
      if (response.status === 409) {
        const choices = ((error as { tenants?: Tenant[] } | undefined)?.tenants ?? []);
        tenants = choices;
        tenant = choices[0]?.id ?? '';
        message = 'This email belongs to more than one tenant. Choose one and enter your password again.';
      } else if (response.status === 429) {
        message = 'Too many failed attempts. Try again later.';
      } else {
        message = 'Sign-in failed';
      }
    } catch { message = 'Unable to reach the server.'; }
    finally { password = ''; pending = false; }
  }

  function emailChanged() {
    if (!tenants.length) return;
    tenants = [];
    tenant = '';
  }
</script>

<h1 class="text-2xl">Sign in</h1>
<form class="mt-4 flex max-w-sm flex-col gap-3" on:submit|preventDefault={submit}>
  <label>Email <input class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" type="email" required bind:value={email} on:input={emailChanged} autocomplete="username" /></label>
  {#if tenants.length}
    <label>Tenant
      <select class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" bind:value={tenant}>
        {#each tenants as choice (choice.id)}<option value={choice.id}>{choice.name}</option>{/each}
      </select>
    </label>
  {:else}
    <label>Tenant (optional) <input class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" type="text" bind:value={tenant} autocomplete="organization" /></label>
  {/if}
  <label>Password <input class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" type="password" required bind:value={password} autocomplete="current-password" /></label>
  <button type="submit" disabled={pending} class="border border-[var(--line)] px-3 py-1 text-left">{pending ? 'Signing in…' : 'Continue'}</button>
  {#if message}<p role="alert">{message}</p>{/if}
</form>
