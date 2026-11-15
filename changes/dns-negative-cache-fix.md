Fixed

- Only DNS resolutions that yield at least one address are cached now:
  failed lookups (NXDOMAIN, SERVFAIL, NODATA), responses rejected by a
  response rule, and positive answers carrying no addresses (such as a
  CNAME-only reply) are no longer stored, so a domain stops being
  unresolvable for a cached failure's TTL.
