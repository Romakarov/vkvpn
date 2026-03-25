---
name: nextjs-performance
description: >
  Next.js 14+ performance optimization for e-commerce.
  Use when: optimizing page load, fixing hydration issues, configuring caching,
  lazy loading images, reducing bundle size, or improving Core Web Vitals.
  Triggers on: performance, loading, cache, lazy, bundle, optimize, slow, SSR, ISR.
---

# Next.js Performance Optimization

## Server vs Client Components

### Default: Server Components
Server components for everything that doesn't need interactivity:
- Product listings, category pages, order history
- Layout, navigation, footer
- Data fetching and display

### Client Components ONLY for:
- Form inputs and interactive controls
- Cart (add/remove/quantity changes)
- Real-time price calculator (custom amount input)
- Payment status polling
- Theme/currency toggle
- Search with autocomplete

### Rule: Push client boundary DOWN
```
// BAD: entire page is client
'use client'
export default function ProductPage() { ... }

// GOOD: only interactive part is client
export default function ProductPage() {          // server
  return (
    <ProductInfo product={product} />            // server
    <AddToCartButton productId={product.id} />   // client
  )
}
```

## Caching Strategy

### Static pages (ISR)
Homepage, category pages — revalidate every 60s:
```typescript
export const revalidate = 60;
```

### Dynamic pages
Cart, checkout, admin — no cache:
```typescript
export const dynamic = 'force-dynamic';
```

### API route caching
Product list API — cache 30s:
```typescript
return NextResponse.json(data, {
  headers: { 'Cache-Control': 'public, s-maxage=30, stale-while-revalidate=60' }
});
```

## Image Optimization
- ALWAYS use `next/image` — never raw `<img>`
- Set explicit `width` and `height` to prevent layout shift
- Use `priority` on above-the-fold images (hero, first product row)
- Use `loading="lazy"` for below-the-fold (default behavior)
- Use WebP/AVIF formats via Next.js image optimization
- Configure `remotePatterns` in `next.config.js` for external images

```typescript
<Image
  src={product.image_url}
  alt={product.name}
  width={400}
  height={400}
  priority={isAboveFold}
  className="object-cover"
/>
```

## Bundle Size
- Use dynamic imports for heavy components:
```typescript
const QRCode = dynamic(() => import('@/components/QRCode'), {
  loading: () => <Skeleton className="w-48 h-48" />,
  ssr: false,
});
```
- NEVER import entire icon libraries — use tree-shakeable imports:
```typescript
// BAD
import { icons } from 'lucide-react';
// GOOD
import { ShoppingCart } from 'lucide-react';
```
- Analyze bundle: `ANALYZE=true next build`

## Data Fetching
- Fetch data in server components, not in useEffect
- Use parallel fetching with Promise.all:
```typescript
const [products, categories, rates] = await Promise.all([
  getProducts(tenantId),
  getCategories(tenantId),
  getExchangeRates(),
]);
```
- Use React `cache()` for deduplication within a single request
- Use `unstable_cache` for cross-request caching with tags

## Loading States
- Add `loading.tsx` to every route group for instant skeleton UI
- Use Suspense boundaries around slow data:
```typescript
<Suspense fallback={<ProductGridSkeleton />}>
  <ProductGrid categoryId={id} />
</Suspense>
```

## Core Web Vitals Targets
- LCP < 2.5s (optimize hero image, preload fonts)
- FID < 100ms (minimize client JS, defer non-critical scripts)
- CLS < 0.1 (set image dimensions, avoid layout shifts)
