import { expect, test } from '@playwright/test'

// Blueprint 29 E2E: reset -> load -> pipeline -> open critical incident -> brief -> feedback -> evaluation.
test('golden demo path', async ({ page, request }) => {
  await request.post('/api/v1/demo/reset')
  await page.goto('/')
  await page.getByRole('button', { name: 'Load Demo' }).first().click()
  await expect(page.getByText('Raw alerts received')).toBeVisible({ timeout: 30_000 })
  await page.getByRole('button', { name: 'Run Intelligence Pipeline' }).click()
  await expect(page.getByText('Pipeline complete')).toBeVisible({ timeout: 60_000 })

  await page.getByRole('link', { name: /privileged account compromise: finance-admin/ }).first().click()
  await expect(page.getByRole('heading', { name: /Why risk =/ })).toBeVisible()
  await expect(page.getByText('Observed facts · cited')).toBeVisible()

  // One click from AI claim to cited evidence.
  await page.locator('button[title="Open source alert evidence"]').first().click()
  await expect(page.getByText('Immutable raw payload')).toBeVisible()
  await page.keyboard.press('Escape')

  await page.getByRole('button', { name: 'Confirmed malicious' }).click()
  await expect(page.getByText('confirmed malicious').first()).toBeVisible()

  await page.getByRole('link', { name: 'Evaluation Lab' }).first().click()
  await expect(page.getByText('Top-3 critical recall')).toBeVisible()
})
