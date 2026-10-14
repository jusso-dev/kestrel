<script lang="ts">
  let email = '';
  let password = '';
  let message = '';

  async function submit() {
    const response = await fetch('/api/v1/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    message = response.ok ? 'Signed in' : 'Sign-in failed';
    password = '';
  }
</script>

<h1 class="text-2xl">Sign in</h1>
<form class="mt-4 flex max-w-sm flex-col gap-3" on:submit|preventDefault={submit}>
  <label>Email <input class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" bind:value={email} autocomplete="username" /></label>
  <label>Password <input class="mt-1 block w-full border border-[var(--line)] bg-transparent px-2 py-1" type="password" bind:value={password} autocomplete="current-password" /></label>
  <button type="submit" class="border border-[var(--line)] px-3 py-1 text-left">Continue</button>
  {#if message}<p>{message}</p>{/if}
</form>
