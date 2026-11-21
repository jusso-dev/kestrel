<script lang="ts">
  import { untrack } from 'svelte';
  import { page } from '$app/state';
  import { goto } from '$app/navigation';
  import { request, list, type Resource } from '#lib/api/client.ts';
  import TimeSeries from '#lib/TimeSeries.svelte';
  import TimeRange from '#lib/TimeRange.svelte';
  import SingleStat from '#lib/SingleStat.svelte';
  import Problems from '#lib/Problems.svelte';
  type Widget = { type: 'graph' | 'stat' | 'problems'; title: string; query: string };
  type Dashboard = Resource & { layout?: Widget[] };
  let dashboards = $state<Dashboard[]>([]);
  let widgets = $state<Widget[]>([]);
  let name = $state('New dashboard');
  let range = $state('1h');
  let customStart = $state('');
  let customEnd = $state('');
  let type = $state<Widget['type']>('graph');
  let title = $state('');
  let query = $state('kestrel_cpu_usage_ratio');
  let message = $state('');
  let saving = $state(false);
  let loaded = $state(false);
  let generation = 0;
  async function load(id: string) {
    const current = ++generation;
    loaded = false;
    message = '';
    try {
      const [available, dashboard] = await Promise.all([
        list<Dashboard>('/dashboards'), id === 'home' ? Promise.resolve(undefined) : request<Dashboard>('/dashboards/' + encodeURIComponent(id))
      ]);
      if (current !== generation) return;
      dashboards = available;
      name = dashboard?.name ?? 'New dashboard';
      // Existing dashboards may predate widget layouts or contain JSON saved
      // by another client. Ignore unsupported entries instead of crashing.
      widgets = Array.isArray(dashboard?.layout) ? dashboard.layout.filter((widget) =>
        widget && ['graph', 'stat', 'problems'].includes(widget.type) && typeof widget.title === 'string' && typeof widget.query === 'string') : [];
      loaded = true;
    } catch (cause) { if (current === generation) message = cause instanceof Error ? cause.message : 'Unable to load dashboard.'; }
  }
  $effect(() => {
    const id = page.params.id;
    if (id) untrack(() => { void load(id); });
  });
  function add(event: SubmitEvent) {
    event.preventDefault();
    if (!title.trim() || (type !== 'problems' && !query.trim())) return;
    widgets = [...widgets, { type, title: title.trim(), query: query.trim() }];
    title = '';
  }
  async function save() {
    if (saving) return;
    saving = true;
    try {
      const isNew = page.params.id === 'home';
      const saved = await request<Dashboard>('/dashboards' + (isNew ? '' : '/' + encodeURIComponent(page.params.id ?? '')), {
        method: isNew ? 'POST' : 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name, layout: widgets })
      });
      if (isNew) await goto('/dashboards/' + encodeURIComponent(saved.id));
      message = 'Dashboard saved.';
    } catch (cause) { message = cause instanceof Error ? cause.message : 'Unable to save dashboard.'; }
    finally { saving = false; }
  }
</script>
<h1 class="text-2xl">Dashboards</h1>
<nav class="my-3 flex flex-wrap gap-3" aria-label="Saved dashboards">
  <a class="underline" href="/dashboards/home">New dashboard</a>
  {#each dashboards as dashboard}<a class="underline" href={'/dashboards/' + encodeURIComponent(dashboard.id)}>{dashboard.name ?? dashboard.id}</a>{/each}
</nav>
{#if message}<p role="status">{message}</p>{/if}
{#if loaded}
  <label>Name <input class="border border-[var(--line)] bg-transparent" bind:value={name} /></label>
  <button type="button" class="ml-3 border border-[var(--line)] px-3 py-1" disabled={saving || !name.trim()} onclick={save}>Save dashboard</button>
  <TimeRange bind:range bind:customStart bind:customEnd />
  <form class="my-4 flex flex-wrap gap-3" onsubmit={add}>
    <label>Widget type <select class="bg-[var(--bg)]" bind:value={type}><option value="graph">Graph</option><option value="stat">Single stat</option><option value="problems">Problem list</option></select></label>
    <label>Title <input required class="border border-[var(--line)] bg-transparent" bind:value={title} /></label>
    {#if type !== 'problems'}<label>Query <input required class="border border-[var(--line)] bg-transparent" bind:value={query} /></label>{/if}
    <button type="submit" class="border border-[var(--line)] px-3 py-1">Add widget</button>
  </form>
  <div class="grid gap-6 lg:grid-cols-2">
    {#each widgets as widget, index}
      <article class="min-w-0 border border-[var(--line)] p-4">
        <button type="button" class="mb-2 underline" aria-label={'Remove ' + widget.title} onclick={() => { widgets = widgets.filter((_, i) => i !== index); }}>Remove</button>
        {#key `${widget.type}:${widget.title}:${widget.query}:${range}:${customStart}:${customEnd}`}
          {#if widget.type === 'graph'}<TimeSeries title={widget.title} query={widget.query} {range} {customStart} {customEnd} />
          {:else if widget.type === 'stat'}<h2>{widget.title}</h2><SingleStat query={widget.query} />
          {:else}<h2>{widget.title}</h2><Problems filters={false} />{/if}
        {/key}
      </article>
    {/each}
  </div>
{/if}
