<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';
  import { onMount } from 'svelte';

  const links = [
    ['/', 'Overview'],
    ['/problems', 'Problems'],
    ['/hosts', 'Hosts'],
    ['/dashboards/home', 'Dashboards'],
    ['/configuration', 'Configuration'],
    ['/administration', 'Administration']
  ];

  let dark = false;
  onMount(() => {
    dark = localStorage.getItem('kestrel-theme') === 'dark';
    document.documentElement.classList.toggle('dark', dark);
  });

  function toggle() {
    dark = !dark;
    document.documentElement.classList.toggle('dark', dark);
    localStorage.setItem('kestrel-theme', dark ? 'dark' : 'light');
  }
</script>

<div class="min-h-screen md:grid md:grid-cols-[15rem_minmax(0,1fr)]">
  <aside class="border-b border-[var(--line)] px-6 py-4 md:border-b-0 md:border-r">
    <div class="mb-3 flex items-center justify-between">
      <strong>Kestrel</strong>
      <button type="button" on:click={toggle}>{dark ? 'Light' : 'Dark'}</button>
    </div>
    <nav class="flex flex-wrap gap-4 text-sm md:flex-col">
      {#each links as [href, label]}
        <a href={href} class:font-semibold={$page.url.pathname === href}>{label}</a>
      {/each}
      <a href="/login">Sign in</a>
    </nav>
  </aside>
  <main class="px-6 py-6">
    <slot />
  </main>
</div>
