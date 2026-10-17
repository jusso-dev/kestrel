<script lang="ts">
  import { goto } from '$app/navigation';
  import { api } from '$lib/api/client';
  let email = '';
  let password = '';
  let message = '';
  let pending = false;

  async function submit() {
    if (pending) return;
    pending = true;
    message = '';
    try {
      const { response } = await api.POST('/api/v1/login', { body: { email, password } });
      if (response.ok) await goto('/');
      else message = 'Sign-in failed';
    } catch { message = 'Unable to reach the server.'; }
    finally { password = ''; pending = false; }
  }
</script>

<h1 class="text-2xl">Sign in</h1>
<form class="mt-4 flex max-w-sm flex-col gap-3" on:submit|preventDefault={submit}>
  <label>Email <input class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" type="email" required bind:value={email} autocomplete="username" /></label>
  <label>Password <input class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" type="password" required bind:value={password} autocomplete="current-password" /></label>
  <button type="submit" disabled={pending} class="border border-[var(--line)] px-3 py-1 text-left">{pending ? 'Signing in…' : 'Continue'}</button>
  {#if message}<p role="alert">{message}</p>{/if}
</form>
