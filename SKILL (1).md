---
name: playwright-e2e
description: >
  E2E testing skill for digital goods store. Writes and runs Playwright tests
  that simulate real user flows: browsing catalog, adding to cart, checkout,
  payment, receiving codes. Use when: creating pages, completing features,
  or when user says "e2e", "тест", "протестируй", "проверь флоу".
---

# Playwright E2E Testing

## Setup
Ensure Playwright is installed: `npx playwright install chromium`

## Test Structure
All tests in `tests/e2e/`. One file per flow:

### Critical Flows to Test

**1. Guest Purchase Flow (INSTANT_CODE):**
1. Open homepage → verify categories load
2. Click category → verify products load
3. Click product → verify price in RUB and KGS
4. Click "Купить сразу" → checkout page
5. Enter email → click "Оплатить"
6. Verify QR code page shows with timer
7. Simulate payment webhook (mock)
8. Verify code appears on page
9. Verify order status = COMPLETED

**2. Cart Flow:**
1. Add 3 products to cart
2. Open cart → verify items and total
3. Remove 1 item → verify total updates
4. Proceed to checkout → verify correct amount

**3. Free Amount Flow (Telegram Stars / Steam):**
1. Open Telegram Stars product
2. Enter custom amount (e.g., 500)
3. Verify price calculates correctly in both currencies
4. Proceed through checkout

**4. Auth Flow:**
1. Register with email + password
2. Login
3. Make purchase
4. Check order appears in personal cabinet
5. Logout → login again → history persists

**5. Admin Flow:**
1. Login as admin
2. Create product
3. Upload codes (CSV)
4. Verify codes appear in inventory
5. Process manual order

**6. Multi-tenant Flow:**
1. Open site via domain A → verify theme A loads
2. Open site via domain B → verify theme B loads
3. Verify different products per tenant

**7. Merchant API Flow:**
1. POST /api/merchant/invoice with amount
2. Verify QR returned
3. Simulate payment webhook
4. Verify merchant balance increased
5. Verify callback sent to merchant webhook_url

## Rules
- ALWAYS use data-testid attributes for selectors, never CSS classes
- ALWAYS clean up test data after each test (use beforeEach/afterEach)
- ALWAYS test both success and error paths
- Test mobile viewport (375px) for critical flows
- Use page.waitForResponse() for API calls, not arbitrary timeouts
