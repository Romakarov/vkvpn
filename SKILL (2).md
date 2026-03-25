---
name: prisma-db
description: >
  Database and Prisma best practices for multi-tenant e-commerce.
  Use when: creating/modifying Prisma schema, writing migrations,
  writing database queries, or optimizing query performance.
  Triggers on: schema.prisma, prisma, migration, query, database, index.
---

# Prisma & Database Best Practices

## Schema Rules

### Indexes (CRITICAL for performance)
Every query pattern needs an index. For this project:
- `Order`: index on (tenant_id, status), (tenant_id, created_at), (merchant_id), (order_number), (guest_email)
- `Product`: index on (category_id, is_active), (slug)
- `TenantProduct`: composite unique on (tenant_id, product_id)
- `CodeInventory`: index on (product_id, is_used), partial index where is_used = false
- `CartItem`: index on (session_id, tenant_id), (user_id, tenant_id)
- `MerchantTransaction`: index on (merchant_id, created_at)
- `SupportChat`: index on (tenant_id, status)
- `ExchangeRate`: index on (pair, fetched_at DESC)

### Multi-tenant Isolation
- EVERY query that returns data to a user MUST filter by tenant_id
- Use Prisma middleware or extension to auto-inject tenant_id filter:
```typescript
prisma.$extends({
  query: {
    $allOperations({ args, query, model }) {
      if (tenantModels.includes(model) && currentTenantId) {
        args.where = { ...args.where, tenant_id: currentTenantId };
      }
      return query(args);
    }
  }
})
```
- NEVER allow cross-tenant data access except for SUPERADMIN

## Migrations
- ALWAYS use `prisma migrate dev --name descriptive-name`
- NEVER edit existing migrations — create new ones
- ALWAYS seed test data: `prisma/seed.ts`
- Use `@default(uuid())` for public-facing IDs
- Use `@default(autoincrement())` only for internal IDs
- Decimal for money: `Decimal @db.Decimal(19, 4)` — never Float

## Query Patterns
- Use `select` to pick only needed fields (not include everything)
- Use transactions for: payment processing, code assignment, balance updates
```typescript
await prisma.$transaction(async (tx) => {
  const code = await tx.codeInventory.findFirst({
    where: { product_id: productId, is_used: false }
  });
  if (!code) throw new Error('No codes available');
  await tx.codeInventory.update({
    where: { id: code.id },
    data: { is_used: true, order_id: orderId, used_at: new Date() }
  });
  return code;
});
```
- ALWAYS use transactions when updating balance + creating transaction record
- Use findFirst + update in transaction for atomic code assignment (prevents race conditions)

## Soft Deletes
- Products, Categories: use `is_active` flag, never hard delete
- Orders: never delete, only status change
- Codes: never delete, mark as used
