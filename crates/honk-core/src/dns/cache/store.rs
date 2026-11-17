use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{
    CacheKey, CacheSlot, CacheValue, CachedEntry, DnsCacheService, PublicationEpoch, lock,
};

pub(crate) enum ExactLookup {
    Positive { entry: CachedEntry, revision: u64 },
    Miss,
}

impl DnsCacheService {
    pub fn get(&self, key: &str) -> Option<CachedEntry> {
        self.get_slot(&CacheSlot::Legacy(key.to_owned()))
    }

    #[cfg(test)]
    pub(crate) fn get_exact(&self, key: &CacheKey) -> Option<CachedEntry> {
        self.get_slot(&CacheSlot::Exact(key.clone()))
    }

    pub(crate) fn lookup_exact(&self, key: &CacheKey, require_strict: bool) -> ExactLookup {
        let key = CacheSlot::Exact(key.clone());
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);

        let (positive, clear_positive) = match shard.get(&key) {
            Some(value) => match value.positive.as_ref() {
                Some(entry) if entry.is_stale_retention_exceeded() => (None, true),
                Some(entry) if require_strict && !entry.strict_reusable => (None, false),
                Some(entry) if !entry.is_expired() => (
                    Some(ExactLookup::Positive {
                        entry: entry.clone(),
                        revision: value.revision,
                    }),
                    false,
                ),
                Some(_) | None => (None, false),
            },
            None => (None, false),
        };
        if clear_positive {
            shard.drop_positive(&key);
        }
        let result = positive.unwrap_or(ExactLookup::Miss);

        match &result {
            ExactLookup::Positive { .. } => {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
                tracing::debug!(result = "hit", "DNS cache lookup");
            }
            ExactLookup::Miss => {
                self.counters.misses.fetch_add(1, Ordering::Relaxed);
                crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheMiss);
                tracing::debug!(result = "miss", "DNS cache lookup");
            }
        }
        result
    }

    pub(crate) fn get_stale_exact(
        &self,
        key: &CacheKey,
        require_strict: bool,
    ) -> Option<(CachedEntry, u64)> {
        self.get_stale_slot(&CacheSlot::Exact(key.clone()), require_strict)
    }

    fn get_slot(&self, key: &CacheSlot) -> Option<CachedEntry> {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        let (result, clear_positive) = match shard.get(key) {
            Some(value) => match value.positive.as_ref() {
                Some(entry) if entry.is_stale_retention_exceeded() => (None, true),
                Some(entry) if !entry.is_expired() => (Some(entry.clone()), false),
                Some(_) | None => (None, false),
            },
            None => (None, false),
        };
        if clear_positive {
            shard.drop_positive(key);
        }
        if result.is_some() {
            self.counters.hits.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheHit);
            tracing::debug!(result = "hit", "DNS cache lookup");
        } else {
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheMiss);
            tracing::debug!(result = "miss", "DNS cache lookup");
        }
        result
    }

    pub fn get_stale(&self, key: &str) -> Option<CachedEntry> {
        self.get_stale_slot(&CacheSlot::Legacy(key.to_owned()), false)
            .map(|(entry, _)| entry)
    }

    fn get_stale_slot(&self, key: &CacheSlot, require_strict: bool) -> Option<(CachedEntry, u64)> {
        let index = self.shard_index(key);
        let mut shard = lock(&self.shards[index]);
        let result = shard.get(key).and_then(|value| {
            value
                .positive
                .as_ref()
                .filter(|entry| !require_strict || entry.strict_reusable)
                .filter(|entry| entry.is_expired() && !entry.is_stale_retention_exceeded())
                .map(|entry| (entry.clone(), value.revision))
        });
        if result.is_some() {
            self.counters.stale.fetch_add(1, Ordering::Relaxed);
            crate::stats::record_dns_event(crate::stats::DnsStatEvent::CacheStale);
            tracing::debug!(result = "stale", "DNS cache lookup");
        }
        result
    }

    pub fn put(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        let publication = lock(&self.publication);
        if !publication.accepting {
            return;
        }
        let ttl = min_ttl.max(1);
        let _ = self.put_slot(CacheSlot::Legacy(key), response.into(), ttl, true, None);
    }

    #[cfg(test)]
    /// Publish a positive answer. `refreshing` is the slot revision a background
    /// refresh started from; `None` publishes unconditionally.
    pub(crate) fn put_exact(
        &self,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
        refreshing: Option<u64>,
    ) {
        let publication = lock(&self.publication);
        if publication.accepting {
            let _ = self.publish_exact(key, response, min_ttl, refreshing);
        }
    }

    fn publish_exact(
        &self,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
        refreshing: Option<u64>,
    ) -> Option<u64> {
        let ttl = min_ttl.max(1);
        let response = bytes::Bytes::from(response);
        let retained = self.put_slot(
            CacheSlot::Exact(key.clone()),
            response.clone(),
            ttl,
            true,
            refreshing,
        );
        if retained.is_some()
            && let Some(persister) = lock(&self.persister).clone()
        {
            persister.save(
                key,
                response,
                crate::dns::persist::unix_now() + u64::from(ttl),
            );
        }
        retained
    }

    pub(crate) fn put_exact_if_current(
        &self,
        epoch: PublicationEpoch,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
        refreshing: Option<u64>,
    ) -> Option<u64> {
        let publication = lock(&self.publication);
        if !publication.accepting || publication.epoch != epoch.0 {
            return None;
        }
        self.publish_exact(key, response, min_ttl, refreshing)
    }

    pub(crate) fn put_restored_exact_if_current(
        &self,
        epoch: PublicationEpoch,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
    ) -> bool {
        let publication = lock(&self.publication);
        publication.accepting
            && publication.epoch == epoch.0
            && self
                .put_slot(CacheSlot::Exact(key), response.into(), min_ttl, false, None)
                .is_some()
    }

    fn put_slot(
        &self,
        key: CacheSlot,
        response: bytes::Bytes,
        min_ttl: u32,
        strict_reusable: bool,
        refreshing: Option<u64>,
    ) -> Option<u64> {
        if response.len() > super::service::MAX_ANSWER_BYTES
            || crate::dns::response::is_truncated(&response)
        {
            return None;
        }
        let ttl = min_ttl.max(1);
        let entry = CachedEntry {
            response,
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl)),
            min_ttl,
            strict_reusable,
        };
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);
        if refreshing.is_some_and(|revision| {
            !shard
                .peek(&key)
                .is_some_and(|value| value.revision == revision && value.positive.is_some())
        }) {
            return None;
        }
        let revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
        shard.put(key, CacheValue::positive(entry, revision));
        Some(revision)
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_for_test(&self, key: String, response: Vec<u8>, min_ttl: u32) {
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);
        let revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
        shard.put(
            key,
            CacheValue::positive(
                CachedEntry {
                    response: response.into(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                    min_ttl,
                    strict_reusable: true,
                },
                revision,
            ),
        );
    }

    #[cfg(test)]
    pub(crate) fn insert_expired_exact_for_test(
        &self,
        key: CacheKey,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let key = CacheSlot::Exact(key);
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);
        let revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
        shard.put(
            key,
            CacheValue::positive(
                CachedEntry {
                    response: response.into(),
                    expires_at: Instant::now() - Duration::from_secs(1),
                    min_ttl,
                    strict_reusable: true,
                },
                revision,
            ),
        );
    }
    #[cfg(test)]
    pub(crate) fn expire_positive_exact_for_test(&self, key: &CacheKey) {
        let key = CacheSlot::Exact(key.clone());
        let index = self.shard_index(&key);
        *lock(&self.shards[index])
            .positive_expiry_mut(&key)
            .expect("positive cache fixture") = Instant::now() - Duration::from_secs(1);
    }

    #[cfg(test)]
    pub(crate) fn insert_beyond_stale_retention_for_test(
        &self,
        key: String,
        response: Vec<u8>,
        min_ttl: u32,
    ) {
        let key = CacheSlot::Legacy(key);
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);
        let revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
        shard.put(
            key,
            CacheValue::positive(
                CachedEntry {
                    response: response.into(),
                    expires_at: Instant::now()
                        - super::storage::STALE_RETENTION
                        - Duration::from_secs(1),
                    min_ttl,
                    strict_reusable: true,
                },
                revision,
            ),
        );
    }

    /// Publish an empty replacement, retaining the refresh owner's revision fence.
    pub(crate) fn supersede_exact_if_current(
        &self,
        epoch: PublicationEpoch,
        key: CacheKey,
        refreshing: Option<u64>,
    ) {
        let publication = lock(&self.publication);
        if !publication.accepting || publication.epoch != epoch.0 {
            return;
        }
        let key = CacheSlot::Exact(key);
        let index = self.shard_index(&key);
        let mut shard = lock(&self.shards[index]);
        if refreshing.is_some_and(|revision| {
            !shard
                .peek(&key)
                .is_some_and(|value| value.revision == revision && value.positive.is_some())
        }) {
            return;
        }
        if shard.pop(&key).is_some() {
            self.next_revision.fetch_add(1, Ordering::Relaxed);
        }
    }
}
