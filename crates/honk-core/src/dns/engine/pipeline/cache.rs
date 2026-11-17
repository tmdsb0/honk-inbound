use std::time::Instant;

use tracing::debug;

use super::super::effective_expiry;
use super::ExecutionContext;
use crate::dns::cache::{CacheKey, ExactLookup, OperationKind};
use crate::dns::forwarder::{
    CacheAccess, DnsForwardError, ResolveMode, extract_min_ttl_including_zero, rewrite_answer_ttls,
};
use crate::dns::outcome::{DnsOutcome, EffectiveExpiry, OutcomeStatus, Provenance, ResponseClass};
#[cfg(feature = "native-api")]
use crate::dns::query::IngressProfile;

#[cfg(feature = "native-api")]
pub(super) fn entry_id_demanded(context: &ExecutionContext<'_>) -> bool {
    matches!(context.prepared.query().ingress(), IngressProfile::Api)
        || crate::observe::flows::dns::cache_entry_demanded()
}

pub(super) async fn lookup(
    context: &ExecutionContext<'_>,
    allow_refresh: bool,
) -> Result<Option<DnsOutcome>, DnsForwardError> {
    if !context.forwarder.cache_enabled || context.options.cache != CacheAccess::Normal {
        return Ok(None);
    }
    let cache = context.forwarder.cache_service().await;
    crate::observe::flows::dns::cache_state("miss");
    let (entry, revision) = match cache.lookup_exact(
        &context.cache_key,
        matches!(context.mode, ResolveMode::Strict),
    ) {
        ExactLookup::Positive { entry, revision } => {
            crate::observe::flows::dns::cache_state("hit");
            (entry, revision)
        }
        ExactLookup::Miss => return Ok(None),
    };
    #[cfg(feature = "native-api")]
    let entry_id = if entry_id_demanded(context) {
        cache.entry_id_for_revision(&context.cache_key, revision)
    } else {
        None
    };
    #[cfg(feature = "native-api")]
    crate::observe::flows::dns::cache_entry(entry_id.as_deref());
    let remaining = entry.remaining_ttl_secs();
    let expires_at = entry.expires_at;
    debug!(remaining, "DNS forwarder: positive cache hit");
    let refresh_after = (entry.min_ttl as u64 / 10).max(1);
    if allow_refresh && remaining <= refresh_after {
        let refresh_key = context.cache_key.with_operation(OperationKind::Refresh);
        context.forwarder.maybe_spawn_refresh(
            context.raw_query,
            context.metadata,
            context.mode,
            refresh_key,
            context.publication_epoch,
            revision,
            context.options,
        );
    }
    let response = entry.response;
    let response = context
        .forwarder
        .apply_prefer_strategy(
            context.raw_query,
            context.prepared.query(),
            context.prepared.qtype(),
            response,
            context.metadata,
            context.mode,
            context.options,
        )
        .await?;
    context
        .forwarder
        .outcome_from_wire(
            context.engine,
            context.prepared,
            response,
            None,
            OutcomeStatus::Accepted,
            Provenance::Cache,
            // Preferred-family probes must not extend the entry's expiry.
            EffectiveExpiry::cacheable(expires_at.saturating_duration_since(Instant::now())),
            None,
            None,
            Vec::new(),
            context.mode,
        )
        .map(|outcome| {
            #[cfg(feature = "native-api")]
            let outcome = outcome.with_cache_entry_id(entry_id);
            Some(outcome)
        })
}

pub(super) async fn store(
    context: &ExecutionContext<'_>,
    cache_key: &CacheKey,
    response: &mut [u8],
    rejected_wire: Option<&[u8]>,
    class: ResponseClass,
) -> (EffectiveExpiry, Option<u64>) {
    let lifetime_wire = rejected_wire.unwrap_or(response);
    if !context.reuse_eligible {
        return (EffectiveExpiry::do_not_cache(), None);
    }
    let fixed_ttl = context
        .forwarder
        .routing
        .fixed_ttl(context.prepared.domain());
    if fixed_ttl == Some(0) {
        return (EffectiveExpiry::do_not_cache(), None);
    }
    // Only a successful resolution that yields an address is cached. A
    // failure, a rejected answer, or an answer without an address leaves the
    // cache slot untouched: the next query re-asks upstream, and an expired
    // positive stays available for serve-stale.
    if rejected_wire.is_some()
        || !is_cacheable_resolution(context.prepared.qtype(), lifetime_wire, class)
    {
        return (EffectiveExpiry::do_not_cache(), None);
    }
    let expiry = effective_expiry(
        fixed_ttl,
        context.forwarder.cache_ttl,
        extract_min_ttl_including_zero(lifetime_wire),
    );
    let mut revision = None;
    if context.forwarder.cache_enabled {
        let cache = context.forwarder.cache_service().await;
        if !expiry.is_cacheable() {
            cache.supersede_exact_if_current(
                context.publication_epoch,
                cache_key.clone(),
                context.refreshing,
            );
        } else {
            let cache_ttl = expiry.ttl().as_secs().min(u64::from(u32::MAX)) as u32;
            rewrite_answer_ttls(response, cache_ttl);
            revision = cache.put_exact_if_current(
                context.publication_epoch,
                cache_key.clone(),
                response.to_owned(),
                cache_ttl,
                context.refreshing,
            );
        }
    }
    (expiry, revision)
}

/// Whether a response is a normal resolution worth caching: a NOERROR
/// positive answer that carries an address of the queried family (an A query
/// needs IPv4, an AAAA query needs IPv6). Any answer records suffice for
/// other query types, so a CNAME-only answer to an address query is not
/// cached.
fn is_cacheable_resolution(qtype: u16, wire: &[u8], class: ResponseClass) -> bool {
    if class != ResponseClass::Positive {
        return false;
    }
    if wire.get(3).copied().unwrap_or_default() & 0x0f != 0 {
        return false;
    }
    crate::dns::forwarder::answer_has_family_address(qtype, wire)
}
