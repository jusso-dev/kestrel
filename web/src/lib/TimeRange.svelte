<script lang="ts">
  export let range = '1h';
  export let customStart = '';
  export let customEnd = '';
</script>
<div class="my-4 flex flex-wrap items-center gap-3">
  <label>Time range
    <select bind:value={range} class="border border-[var(--line)] bg-[var(--bg)] px-2 py-1">
      <option>1h</option><option>6h</option><option>24h</option><option>7d</option><option value="custom">Custom</option>
    </select>
  </label>
  {#if range === 'custom'}
    <label>From <input type="datetime-local" bind:value={customStart} /></label>
    <label>To <input type="datetime-local" bind:value={customEnd} /></label>
  {/if}
</div>
