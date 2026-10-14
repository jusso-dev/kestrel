import { test, expect } from '@playwright/test';

test('sidebar reaches hosts and problems', async ({ page }) => {
  await page.goto('/');
  await page.getByRole('link', { name: 'Problems' }).click();
  await expect(page.getByRole('heading', { name: 'Problems' })).toBeVisible();
  await page.getByRole('link', { name: 'Hosts' }).click();
  await expect(page.getByRole('heading', { name: 'Hosts' })).toBeVisible();
});
