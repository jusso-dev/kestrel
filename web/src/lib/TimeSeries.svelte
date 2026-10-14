<script lang="ts">
  import { onMount } from 'svelte';
  import uPlot from 'uplot';
  import 'uplot/dist/uPlot.min.css';

  export let query = 'up';
  export let range = '1h';

  let host: HTMLDivElement;

  function seconds(value: string): number {
    if (value === '6h') return 6 * 3600;
    if (value === '24h') return 24 * 3600;
    if (value === '7d') return 7 * 24 * 3600;
    return 3600;
  }

  onMount(() => {
    const end = Math.floor(Date.now() / 1000);
    const start = end - seconds(range);
    const plot = new uPlot(
      {
        width: 640,
        height: 240,
        series: [{}, { label: query, stroke: '#9a3412' }]
      },
      [[start, end], [0, 1]],
      host
    );
    const params = new URLSearchParams({
      query,
      start: String(start),
      end: String(end),
      step: '60'
    });
    fetch('/api/v1/metrics/query_range?' + params.toString())
      .then((response) => (response.ok ? response.json() : null))
      .then((body) => {
        const points = body?.series?.[0]?.points;
        if (!Array.isArray(points) || points.length === 0) return;
        plot.setData([
          points.map((point: [number, number]) => point[0]),
          points.map((point: [number, number]) => point[1])
        ]);
      })
      .catch(() => undefined);
    return () => plot.destroy();
  });
</script>

<div bind:this={host}></div>
