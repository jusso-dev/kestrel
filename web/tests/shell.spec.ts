import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/hosts?*', (route) => route.fulfill({ json: { items: [{ id: 'host-1', name: 'web-1', status: 'up' }], next: null } }));
  await page.route('**/api/v1/problems?*', (route) => route.fulfill({ json: { items: [], next: null } }));
  await page.route('**/api/v1/events/stream', (route) => route.fulfill({ contentType: 'text/event-stream', body: ': connected\n\n' }));
});

test('sidebar reaches hosts and problems', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Problems' }).click();
  await expect(page.getByRole('heading', { name: 'Problems' })).toBeVisible();
  await page.getByRole('link', { name: 'Hosts' }).click();
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible();
});

test('production bootstrap works under the embedded server content security policy', async ({ page }) => {
  const violations: string[] = [];
  await page.addInitScript(() => document.addEventListener('securitypolicyviolation', (event) => {
    (window as any).cspViolations ??= [];
    (window as any).cspViolations.push(event.violatedDirective);
  }));
  await page.route('**/*', async (route) => {
    if (route.request().resourceType() !== 'document') return route.fallback();
    const response = await route.fetch();
    const html = await response.text();
    const hashes = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script\s*>/gi)]
      .map((match) => `'sha256-${createHash('sha256').update(match[1]).digest('base64')}'`);
    const announcerStyle = 'position: absolute; left: 0; top: 0; clip: rect(0 0 0 0); clip-path: inset(50%); overflow: hidden; white-space: nowrap; width: 1px; height: 1px';
    const styleHash = createHash('sha256').update(announcerStyle).digest('base64');
    await route.fulfill({ response, headers: { ...response.headers(),
      'content-security-policy': `default-src 'self'; frame-ancestors 'none'; script-src 'self' ${hashes.join(' ')}; style-src-attr 'unsafe-hashes' 'sha256-${styleHash}'` } });
  });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
  await page.getByRole('link', { name: 'Hosts', exact: true }).click();
  await expect(page.getByText('web-1')).toBeVisible();
  await page.route('**/api/v1/hosts/host-1', (route) => route.fulfill({ json: { id: 'host-1', name: 'web-1' } }));
  await page.route('**/api/v1/metrics/query_range?*', (route) => route.fulfill({ json: { series: [{ labels: [['host', 'web-1']], points: [[1700000000, 1], [1700000030, 2]] }] } }));
  await page.getByRole('link', { name: 'web-1', exact: true }).click();
  await expect(page.locator('.uplot')).toHaveCount(7);
  violations.push(...await page.evaluate(() => (window as any).cspViolations ?? []));
  expect(violations).toEqual([]);
});

test('login submits credentials, handles refusal, and navigates on success', async ({ page }) => {
  let attempts = 0;
  await page.route('**/api/v1/login', async (route) => {
    expect(route.request().postDataJSON()).toEqual({ email: 'operator@example.com', password: 'test-password' });
    attempts += 1;
    await route.fulfill({ status: attempts === 1 ? 401 : 200, json: { email: 'operator@example.com' } });
  });
  await page.goto('/login');
  await page.getByLabel('Email').fill('operator@example.com');
  await page.getByLabel('Password').fill('test-password');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('alert')).toHaveText('Sign-in failed');
  await expect(page.getByLabel('Password')).toHaveValue('');
  await page.getByLabel('Password').fill('test-password');
  await page.getByRole('button', { name: 'Continue' }).click();
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible();
});

test('SSE invalidates problems within two seconds and filters/acknowledges', async ({ page }) => {
  await page.addInitScript(() => {
    class FakeEvents extends EventTarget {
      onmessage: (() => void) | null = null;
      onopen: (() => void) | null = null;
      constructor() { super(); (window as any).problemEvents = this; }
      close() {}
    }
    (window as any).EventSource = FakeEvents;
  });
  let items: any[] = [];
  await page.route('**/api/v1/problems?*', (route) => route.fulfill({ json: { items, next: null } }));
  await page.route('**/api/v1/problems/problem-1/ack', async (route) => {
    items[0].acknowledged = true;
    await route.fulfill({ json: items[0] });
  });
  await page.goto('/problems');
  await expect(page.getByText('No matching problems.')).toBeVisible();
  items = [{ id: 'problem-1', name: 'CPU saturated', status: 'open', severity: 'high' }];
  await page.evaluate(() => (window as any).problemEvents.dispatchEvent(new Event('problem')));
  await expect(page.getByText('CPU saturated open high')).toBeVisible({ timeout: 2000 });
  await page.getByLabel('Search').fill('disk');
  await expect(page.getByText('No matching problems.')).toBeVisible();
  await page.getByLabel('Search').fill('CPU');
  await page.getByRole('button', { name: 'Acknowledge', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Acknowledged', exact: true })).toBeDisabled();
});

test('host graphs render seven days of 30-second data for the real host name', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await page.route('**/api/v1/hosts/host-1', (route) => route.fulfill({ json: { id: 'host-1', name: 'web-1' } }));
  const queries: URL[] = [];
  await page.route('**/api/v1/metrics/query_range?*', (route) => {
    const url = new URL(route.request().url());
    queries.push(url);
    const start = Number(url.searchParams.get('start'));
    const end = Number(url.searchParams.get('end'));
    const points = Array.from({ length: Math.floor((end - start) / 30) + 1 }, (_, i) => [start + i * 30, Math.sin(i / 50) + 2]);
    return route.fulfill({ json: { series: [{ labels: [['host', 'web-1']], points }, { labels: [['host', 'web-1'], ['core', '1']], points }] } });
  });
  await page.goto('/hosts/host-1');
  await page.getByLabel('Time range').selectOption('7d');
  await expect(page.locator('.uplot')).toHaveCount(7);
  await expect.poll(() => queries.filter((q) => Number(q.searchParams.get('end')) - Number(q.searchParams.get('start')) === 604800).length).toBe(7);
  expect(queries.every((q) => q.searchParams.get('step') === '30' && q.searchParams.get('query')?.includes('host="web-1"'))).toBeTruthy();
  expect(queries.some((q) => q.searchParams.get('query') === 'rate(snmp_if_in_octets_total{host="web-1"}[5m])')).toBeTruthy();
  expect(queries.some((q) => q.searchParams.get('query') === 'rate(kestrel_network_receive_bytes_total{host="web-1"}[5m])')).toBeTruthy();
  await page.getByLabel('Time range').selectOption('custom');
  await expect(page.getByRole('alert').first()).toHaveText('Choose a valid time range of up to 7 days.');
  expect(errors).toEqual([]);
});

test('dashboard widgets persist as JSON and reload', async ({ page }) => {
  const id = 'dashboard-1';
  let saved: any;
  await page.route('**/api/v1/dashboards?*', (route) => route.fulfill({ json: { items: saved ? [saved] : [], next: null } }));
  await page.route('**/api/v1/dashboards', async (route) => {
    saved = { ...route.request().postDataJSON(), id };
    await route.fulfill({ json: saved });
  });
  await page.route('**/api/v1/dashboards/dashboard-1', async (route) => {
    if (route.request().method() === 'PUT') saved = { ...route.request().postDataJSON(), id };
    await route.fulfill({ json: saved });
  });
  await page.route('**/api/v1/metrics/query?*', (route) => route.fulfill({ json: { series: [{ points: [[1700000000, 42]] }] } }));
  await page.goto('/dashboards/home');
  await page.getByLabel('Name', { exact: true }).fill('Operations');
  await page.getByLabel('Widget type').selectOption('stat');
  await page.getByLabel('Title', { exact: true }).fill('CPU now');
  await page.getByRole('button', { name: 'Add widget' }).click();
  await expect(page.getByText('42', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Save dashboard' }).click();
  await expect(page).toHaveURL(/dashboards\/dashboard-1$/);
  await page.reload();
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue('Operations');
  await expect(page.getByRole('heading', { name: 'CPU now' })).toBeVisible();
  await page.getByRole('button', { name: 'Remove CPU now' }).click();
  await page.getByRole('button', { name: 'Save dashboard' }).click();
  await expect.poll(() => saved.layout.length).toBe(0);
});

test('tenant switching refreshes the administration overview', async ({ page }) => {
  let tenant = 'Home';
  await page.route('**/api/v1/tenants?*', (route) => route.fulfill({ json: { items: [{ id: 'child-1', name: 'Child' }], next: null } }));
  await page.route('**/api/v1/msp/overview', (route) => route.fulfill({ json: { tenant } }));
  await page.route('**/api/v1/session/tenant', async (route) => {
    expect(route.request().postDataJSON()).toEqual({ tenant_id: 'child-1' });
    tenant = 'Child';
    await route.fulfill({ status: 204 });
  });
  await page.goto('/administration');
  await expect(page.locator('pre')).toContainText('Home');
  await page.getByLabel('Tenant').selectOption('child-1');
  await expect(page.locator('pre')).toContainText('Child');
  await expect(page.getByText('Tenant switched', { exact: true })).toBeVisible();
});
