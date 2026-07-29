/**
 * Express 5 delegates string routes to path-to-regexp v8, where anonymous
 * wildcards such as `*` and `/api/v2/*` are invalid. RegExp routes avoid that
 * version-sensitive grammar while keeping these two terminal boundaries exact.
 */
export const V2_API_TREE_ROUTE = /^\/api\/v2(?:\/.*)?$/u;

export const SPA_DOCUMENT_ROUTE = /^\/.*$/u;
