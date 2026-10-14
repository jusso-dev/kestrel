<script lang="ts">
  import '../app.css';
  import { page } from '$app/stores';

  const links = [
    ['/', 'Overview'],
    ['/problems', 'Problems'],
    ['/hosts', 'Hosts'],
    ['/dashboards/home', 'Dashboards'],
    ['/configuration', 'Configuration'],
    ['/administration', 'Administration']
  ];

  let dark = false;

  function toggle() {
    dark = !dark;
    document.documentElement.classList.toggle('dark', dark);
  }
</script>

<div class="min-h-screen">
  <aside class="border-b border-[var(--line)] px-6 py-4">
    <div class="mb-3 flex items-center justify-between">
      <strong>Kestrel</strong>
      <button type="button" on:click={toggle}>{dark ? 'Light' : 'Dark'}</button>
    </div>
    <nav class="flex flex-wrap gap-4 text-sm">
      {#each links as [href, label]}
        <a href={href} class:font-semibold={$page.url.pathname === href}>{label}</a>
      {/each}
    </nav>
  </aside>
  <main class="px-6 py-6">
    <slot />
  </main>
</div>
