<script lang="ts">
  import { onMount } from 'svelte';
  import { list, request, type Resource } from '$lib/api/client';
  export let filters = true;
  let items: Resource[] = [];
  let error = '';
  let search = '';
  let status = '';
  let severity = '';
  let active = true;
  let loading = false;
  let reload = false;
  async function load() {
    if (loading) { reload = true; return; }
    loading = true;
    do {
      reload = false;
      try {
        const next = await list<Resource>('/problems');
        if (active) { items = next; error = ''; }
      } catch (cause) { if (active) error = cause instanceof Error ? cause.message : 'Unable to load problems.'; }
    } while (active && reload);
    loading = false;
  }
  async function ack(id: string) {
    try {
      await request('/problems/' + encodeURIComponent(id) + '/ack', {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ comment: 'Acknowledged from console' })
      });
      await load();
    } catch (cause) { error = cause instanceof Error ? cause.message : 'Unable to acknowledge problem.'; }
  }
  onMount(() => {
    active = true;
    const events = new EventSource('/api/v1/events/stream');
    events.onmessage = () => void load();
    events.addEventListener('problem', () => void load());
    events.onopen = () => void load();
    void load();
    return () => { active = false; events.close(); };
  });
  $: visible = items.filter((item) => (!search || (item.name ?? item.id).toLowerCase().includes(search.toLowerCase())) &&
    (!status || item.status === status) && (!severity || item.severity === severity));
</script>
{#if filters}
  <div class="my-4 flex flex-wrap gap-3">
    <label>Search <input class="border border-[var(--line)] bg-transparent" bind:value={search} /></label>
    <label>Status <select class="bg-[var(--bg)]" bind:value={status}><option value="">All</option>{#each [...new Set(items.map((p) => p.status).filter(Boolean))] as value}<option>{value}</option>{/each}</select></label>
    <label>Severity <select class="bg-[var(--bg)]" bind:value={severity}><option value="">All</option>{#each [...new Set(items.map((p) => p.severity).filter(Boolean))] as value}<option>{value}</option>{/each}</select></label>
  </div>
{/if}
{#if error}<p role="alert">{error}</p>{/if}
<ul class="mt-4 space-y-3" aria-label="Problems">
  {#each visible as problem (problem.id)}
    <li class="flex items-center justify-between gap-4 border border-[var(--line)] px-3 py-2">
      <span>{problem.name ?? problem.id} {problem.status ?? ''} {problem.severity ?? ''}</span>
      <button type="button" disabled={problem.acknowledged || !!problem.acknowledged_at} class="border border-[var(--line)] px-2 py-1" on:click={() => ack(problem.id)}>{problem.acknowledged || problem.acknowledged_at ? 'Acknowledged' : 'Acknowledge'}</button>
    </li>
  {:else}<li>No matching problems.</li>{/each}
</ul>
