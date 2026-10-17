<script lang="ts">
  import { onMount } from 'svelte';
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';
  import { request } from '$lib/api/client';
  export let query = 'up';
  export let title = query;
  export let range = '1h';
  export let customStart = '';
  export let customEnd = '';
  let host: HTMLDivElement;
  let error = '';
  let empty = false;
  onMount(() => {
    let active = true;
    let plot: uPlot | undefined;
    const controller = new AbortController();
    const end = range === 'custom' ? Math.floor(Date.parse(customEnd) / 1000) : Math.floor(Date.now() / 1000);
    const durations: Record<string, number> = { '1h': 3600, '6h': 21600, '24h': 86400, '7d': 604800 };
    const start = range === 'custom' ? Math.floor(Date.parse(customStart) / 1000) : end - (durations[range] ?? 3600);
    const observer = new ResizeObserver(() => plot?.setSize({ width: Math.max(240, host.clientWidth), height: 240 }));
    observer.observe(host);
    async function load() {
      if (!Number.isFinite(start) || !Number.isFinite(end) || start >= end || end - start > 604800) {
        error = 'Choose a valid time range of up to 7 days.';
        return;
      }
      try {
        const params = new URLSearchParams({ query, start: String(start), end: String(end), step: '30' });
        const body = await request<{ series: { labels: [string, string][]; points: [number, number][] }[] }>(
          '/metrics/query_range?' + params, { signal: controller.signal });
        if (!active) return;
        const series = body.series.filter((item) => item.points.length > 0);
        empty = series.length === 0;
        if (empty) return;
        const colors = ['#c2410c', '#0369a1', '#15803d', '#a21caf', '#b45309'];
        const times = [...new Set(series.flatMap((item) => item.points.map(([time]) => time)))].sort((a, b) => a - b);
        const data: uPlot.AlignedData = [times];
        for (const item of series) {
          const values = new Map(item.points);
          data.push(times.map((time) => values.get(time) ?? null));
        }
        plot = new uPlot({ width: Math.max(240, host.clientWidth), height: 240,
          series: [{}, ...series.map((item, index) => ({
            label: item.labels.filter(([key]) => key !== 'tenant').map(([key, value]) => `${key}=${value}`).join(', ') || query,
            stroke: colors[index % colors.length], spanGaps: false
          }))]
        }, data, host);
      } catch (cause) {
        if (active) error = cause instanceof Error ? cause.message : 'Unable to load metrics.';
      }
    }
    void load();
    return () => { active = false; controller.abort(); observer.disconnect(); plot?.destroy(); };
  });
</script>
<section aria-label={title} class="min-w-0">
  <h2 class="font-semibold">{title}</h2>
  {#if error}<p role="alert">{error}</p>{:else if empty}<p>No data for this range.</p>{/if}
  <div bind:this={host} class="w-full overflow-hidden" data-testid="time-series"></div>
</section>
