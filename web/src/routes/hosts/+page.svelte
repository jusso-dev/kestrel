<script lang="ts">
  import { onMount } from 'svelte';

  let items: { id: string; name?: string }[] = [];
  let error = '';

  onMount(async () => {
    const response = await fetch('/api/v1/hosts');
    if (!response.ok) {
      error = 'Sign in to see hosts.';
      return;
    }
    const body = await response.json();
    items = Array.isArray(body.items) ? body.items : [];
  });
</script>

<h1 class="text-2xl">Hosts</h1>
<p class="mt-2 text-[var(--muted)]">Hosts in the groups your role can see.</p>
{#if error}<p class="mt-4">{error}</p>{/if}
<ul class="mt-4 space-y-2">
  {#each items as host}
    <li><a class="underline" href={'/hosts/' + host.id}>{host.name ?? host.id}</a></li>
  {/each}
</ul>
