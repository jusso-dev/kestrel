<script lang="ts">
  import { page } from '$app/stores';
  import TimeSeries from '$lib/TimeSeries.svelte';
  import TimeRange from '$lib/TimeRange.svelte';
  import { request, type Resource } from '$lib/api/client';
  let range = '1h';
  let customStart = '';
  let customEnd = '';
  let host: Resource | undefined;
  let error = '';
  let generation = 0;
  async function load(id: string) {
    const current = ++generation;
    host = undefined;
    error = '';
    try { const next = await request<Resource>('/hosts/' + encodeURIComponent(id)); if (current === generation) host = next; }
    catch (cause) { if (current === generation) error = cause instanceof Error ? cause.message : 'Unable to load host.'; }
  }
  $: if ($page.params.id) void load($page.params.id);
  const metrics: [string, string, boolean][] = [
    ['CPU', 'kestrel_cpu_usage_ratio', false], ['Memory', 'kestrel_memory_used_bytes', false],
    ['Disk', 'kestrel_filesystem_free_bytes', false],
    ['Network received (bytes/s)', 'kestrel_network_receive_bytes_total', true],
    ['Network sent (bytes/s)', 'kestrel_network_transmit_bytes_total', true],
    ['Switch interfaces received (bytes/s)', 'snmp_if_in_octets_total', true],
    ['Switch interfaces sent (bytes/s)', 'snmp_if_out_octets_total', true]
  ];
  function metricQuery(metric: string, rate: boolean, name: string) {
    const selector = metric + '{host=' + JSON.stringify(name) + '}';
    return rate ? 'rate(' + selector + '[5m])' : selector;
  }
</script>
<h1 class="text-2xl">Host {host?.name ?? $page.params.id}</h1>
{#if error}<p role="alert">{error}</p>{/if}
<TimeRange bind:range bind:customStart bind:customEnd />
{#if host}
  <div class="grid gap-6 lg:grid-cols-2">
    {#each metrics as [title, metric, rate]}
      {#key `${host.id}:${range}:${customStart}:${customEnd}`}
        <TimeSeries {title} query={metricQuery(metric, rate, host.name ?? host.id)} {range} {customStart} {customEnd} />
      {/key}
    {/each}
  </div>
{/if}
