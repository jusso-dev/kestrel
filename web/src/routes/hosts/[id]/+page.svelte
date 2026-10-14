<script lang="ts">
  import { page } from '$app/stores';
  import TimeSeries from '$lib/TimeSeries.svelte';
</script>

<h1 class="text-2xl">Host {$page.params.id}</h1>
<div class="mt-4">
  <TimeSeries query={'up{host="' + $page.params.id + '"}'} />
</div>
