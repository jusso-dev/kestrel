<script lang="ts">
  import { page } from '$app/stores';
  import TimeSeries from '$lib/TimeSeries.svelte';

  const ranges = ['1h', '6h', '24h', '7d'];
  let range = '1h';
</script>

<h1 class="text-2xl">Dashboard {$page.params.id}</h1>
<div class="mt-3 flex gap-2">
  {#each ranges as item}
    <button type="button" class:font-semibold={range === item} on:click={() => (range = item)}>{item}</button>
  {/each}
</div>
<div class="mt-4">
  {#key range}
    <TimeSeries query="up" {range} />
  {/key}
</div>
