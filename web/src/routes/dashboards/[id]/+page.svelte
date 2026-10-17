<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { request, list, type Resource } from '$lib/api/client';
  import TimeSeries from '$lib/TimeSeries.svelte';
  import TimeRange from '$lib/TimeRange.svelte';
  import SingleStat from '$lib/SingleStat.svelte';
  import Problems from '$lib/Problems.svelte';
  type Widget = { type: 'graph' | 'stat' | 'problems'; title: string; query: string };
  type Dashboard = Resource & { layout?: Widget[] };
  let dashboards: Dashboard[] = [];
  let widgets: Widget[] = [];
  let name = 'New dashboard';
  let range = '1h';
  let customStart = '';
  let customEnd = '';
  let type: Widget['type'] = 'graph';
  let title = '';
  let query = 'kestrel_cpu_usage_ratio';
  let message = '';
  let saving = false;
  let loaded = false;
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
  $: if ($page.params.id) void load($page.params.id);
  function add() {
    if (!title.trim() || (type !== 'problems' && !query.trim())) return;
    widgets = [...widgets, { type, title: title.trim(), query: query.trim() }];
    title = '';
  }
  async function save() {
    if (saving) return;
    saving = true;
    try {
      const isNew = $page.params.id === 'home';
      const saved = await request<Dashboard>('/dashboards' + (isNew ? '' : '/' + encodeURIComponent($page.params.id ?? '')), {
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
  <button type="button" class="ml-3 border border-[var(--line)] px-3 py-1" disabled={saving || !name.trim()} on:click={save}>Save dashboard</button>
  <TimeRange bind:range bind:customStart bind:customEnd />
  <form class="my-4 flex flex-wrap gap-3" on:submit|preventDefault={add}>
    <label>Widget type <select class="bg-[var(--bg)]" bind:value={type}><option value="graph">Graph</option><option value="stat">Single stat</option><option value="problems">Problem list</option></select></label>
    <label>Title <input required class="border border-[var(--line)] bg-transparent" bind:value={title} /></label>
    {#if type !== 'problems'}<label>Query <input required class="border border-[var(--line)] bg-transparent" bind:value={query} /></label>{/if}
    <button type="submit" class="border border-[var(--line)] px-3 py-1">Add widget</button>
  </form>
  <div class="grid gap-6 lg:grid-cols-2">
    {#each widgets as widget, index}
      <article class="min-w-0 border border-[var(--line)] p-4">
        <button type="button" class="mb-2 underline" aria-label={'Remove ' + widget.title} on:click={() => widgets = widgets.filter((_, i) => i !== index)}>Remove</button>
        {#key `${widget.type}:${widget.title}:${widget.query}:${range}:${customStart}:${customEnd}`}
          {#if widget.type === 'graph'}<TimeSeries title={widget.title} query={widget.query} {range} {customStart} {customEnd} />
          {:else if widget.type === 'stat'}<h2>{widget.title}</h2><SingleStat query={widget.query} />
          {:else}<h2>{widget.title}</h2><Problems filters={false} />{/if}
        {/key}
      </article>
    {/each}
  </div>
{/if}
