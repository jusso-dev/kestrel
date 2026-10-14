<script lang="ts">
  import { onMount } from 'svelte';

  let items: { id: string; name?: string; status?: string }[] = [];
  let error = '';

  async function load() {
    const response = await fetch('/api/v1/problems');
    if (!response.ok) {
      error = 'Sign in to see problems.';
      items = [];
      return;
    }
    error = '';
    const body = await response.json();
    items = Array.isArray(body.items) ? body.items : [];
  }

  async function ack(id: string) {
    const response = await fetch('/api/v1/problems/' + id + '/ack', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ comment: 'acked from the console' })
    });
    if (response.ok) await load();
  }

  onMount(load);
</script>

<h1 class="text-2xl">Problems</h1>
<p class="mt-2 text-[var(--muted)]">Open problems for this tenant.</p>
{#if error}<p class="mt-4">{error}</p>{/if}
<ul class="mt-4 space-y-3">
  {#each items as problem}
    <li class="flex items-center justify-between gap-4 border border-[var(--line)] px-3 py-2">
      <span>{problem.name ?? problem.id} {problem.status ?? ''}</span>
      <button type="button" class="border border-[var(--line)] px-2 py-1" on:click={() => ack(problem.id)}>Acknowledge</button>
    </li>
  {/each}
</ul>
