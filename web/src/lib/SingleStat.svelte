<script lang="ts">
  import { onMount } from 'svelte';
  import { request } from '$lib/api/client';
  export let query: string;
  let value = 'Loading…';
  onMount(() => {
    let active = true;
    request<{ series: { points: [number, number][] }[] }>('/metrics/query?' + new URLSearchParams({ query }))
      .then((body) => {
        const points = body.series[0]?.points;
        if (active) value = points?.length ? String(points[points.length - 1][1]) : 'No data';
      }).catch((cause) => { if (active) value = cause.message; });
    return () => { active = false; };
  });
</script>
<p class="py-6 text-3xl" aria-live="polite">{value}</p>
