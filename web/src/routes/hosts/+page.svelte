<script lang="ts">
  import { onMount } from 'svelte';
  import { list, type Resource } from '$lib/api/client';
  let items: Resource[] = [];
  let error = '';
  onMount(() => {
    let active = true;
    list<Resource>('/hosts').then((next) => { if (active) items = next; })
      .catch((cause) => { if (active) error = cause.message; });
    return () => { active = false; };
  });
</script>
<h1 class="text-2xl">Hosts</h1>
<p class="mt-2 text-[var(--muted)]">Hosts in the groups your role can see.</p>
{#if error}<p role="alert">{error}</p>{/if}
<ul class="mt-4 space-y-2">
  {#each items as host (host.id)}
    <li><a class="underline" href={'/hosts/' + encodeURIComponent(host.id)}>{host.name ?? host.id}</a> <span>{host.status ?? 'Unknown'}</span></li>
  {/each}
</ul>
