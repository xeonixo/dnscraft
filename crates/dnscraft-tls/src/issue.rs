//! ACME DNS-01 issuance orchestration.
//!
//! Publishes Cloudflare TXT records, waits for authoritative propagation,
//! finalizes the order, stores and installs the certificate, then cleans up
//! challenge records.

use std::time::SystemTime;

use tracing::{debug, info, warn};

use crate::acme::{AcmeDirectory, AcmeOrder, Dns01Txt, challenge_txt_name, default_identifiers};
use crate::clock::Clock;
use crate::cloudflare::{CloudflareClient, TTL_ACME_TXT};
use crate::config::TlsConfig;
use crate::error::TlsError;
use crate::propagation::{resolve_nameservers, wait_for_txt};
use crate::resolver::CertResolver;
use crate::store::{CertMeta, CertStore};

/// Issues (or renews) the certificate for `dns.<domain>` + `*.dns.<domain>`.
///
/// On failure the previous certificate on disk and in [`CertResolver`] is left
/// untouched. Challenge TXT cleanup is best-effort.
///
/// When a certificate is already stored, the new order carries its ARI id as
/// `replaces`. Every attempt is recorded in `state.json` (`last_renew_attempt`;
/// on failure `last_error` = stable [`TlsError::code`], on success `last_error`
/// cleared and `last_issue` set); `cert.pem`/`key.pem`/`meta.json` are only
/// written by a successful save.
pub async fn issue<A>(
    acme: &A,
    cloudflare: &CloudflareClient,
    store: &CertStore,
    resolver: &CertResolver,
    cfg: &TlsConfig,
    clock: &dyn Clock,
) -> Result<(), TlsError>
where
    A: AcmeDirectory + AcmeOrder + ?Sized,
{
    if !cfg.acme.enabled {
        return Err(TlsError::config("ACME is disabled"));
    }
    let attempted = clock.now();
    let result = issue_inner(acme, cloudflare, store, resolver, cfg, clock).await;

    let mut state = store.load_state();
    state.last_renew_attempt_unix = Some(unix_secs(attempted));
    match &result {
        Ok(()) => {
            state.last_error = None;
            state.last_issue_unix = Some(unix_secs(clock.now()));
        }
        Err(e) => state.last_error = Some(e.code().to_owned()),
    }
    if let Err(e) = store.save_state(&state) {
        warn!(code = e.code(), "could not persist issue state: {e}");
    }
    result
}

fn unix_secs(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

async fn issue_inner<A>(
    acme: &A,
    cloudflare: &CloudflareClient,
    store: &CertStore,
    resolver: &CertResolver,
    cfg: &TlsConfig,
    clock: &dyn Clock,
) -> Result<(), TlsError>
where
    A: AcmeDirectory + AcmeOrder + ?Sized,
{
    acme.ensure_account(store, &cfg.acme).await?;

    let identifiers = default_identifiers(&cfg.public_domain);
    let challenge_name = challenge_txt_name(&identifiers[0]);

    // Orphan cleanup: drop any leftover `_acme-challenge` TXT from a prior run.
    {
        let _guard = cloudflare.write_guard().await;
        cleanup_challenge_txt(cloudflare, &challenge_name).await;
    }

    // Renewal: tell the CA which certificate this order replaces (ARI).
    let replaces = store.load().ok().flatten().and_then(|c| {
        c.meta
            .ari_cert_id
            .or_else(|| acme.certificate_id(&c.chain_pem))
    });

    let txts = match acme
        .start_dns01_order(store, &cfg.acme, &identifiers, replaces.as_deref())
        .await
    {
        Ok(t) => t,
        Err(e) => {
            acme.abort_order().await;
            return Err(e);
        }
    };

    if let Err(e) = publish_and_wait(cloudflare, &txts, &challenge_name, cfg, clock).await {
        acme.abort_order().await;
        let _guard = cloudflare.write_guard().await;
        cleanup_challenge_txt(cloudflare, &challenge_name).await;
        return Err(e);
    }

    let (chain_pem, key_pem) = match acme.finish_dns01_order(cfg.key_type).await {
        Ok(pair) => pair,
        Err(e) => {
            acme.abort_order().await;
            let _guard = cloudflare.write_guard().await;
            cleanup_challenge_txt(cloudflare, &challenge_name).await;
            return Err(e);
        }
    };

    // Persist + install only after a complete chain; failure here keeps the
    // previous cert (store.save validates before writing).
    let meta = CertMeta {
        identifiers: identifiers.to_vec(),
        ari_cert_id: acme.certificate_id(&chain_pem),
        ..CertMeta::default()
    };
    if let Err(e) = store.save(&chain_pem, &key_pem, &meta) {
        let _guard = cloudflare.write_guard().await;
        cleanup_challenge_txt(cloudflare, &challenge_name).await;
        return Err(e);
    }
    if let Err(e) = resolver.install(&chain_pem, &key_pem) {
        // Disk has the new cert; try to keep resolver in sync — if install
        // fails the previous in-memory cert remains (install is atomic swap).
        warn!("issued cert saved but resolver install failed: {e}");
        let _guard = cloudflare.write_guard().await;
        cleanup_challenge_txt(cloudflare, &challenge_name).await;
        return Err(e);
    }

    {
        let _guard = cloudflare.write_guard().await;
        cleanup_challenge_txt(cloudflare, &challenge_name).await;
    }

    info!(
        domain = %cfg.public_domain,
        "issued and installed TLS certificate"
    );
    Ok(())
}

async fn publish_and_wait(
    cloudflare: &CloudflareClient,
    txts: &[Dns01Txt],
    challenge_name: &str,
    cfg: &TlsConfig,
    clock: &dyn Clock,
) -> Result<(), TlsError> {
    let values: Vec<String> = txts.iter().map(|t| t.value.clone()).collect();
    // All challenges for apex+wildcard share one owner name; still create each
    // value as a separate TXT (add, never upsert).
    {
        let _guard = cloudflare.write_guard().await;
        for t in txts {
            debug!(name = %t.name, "creating ACME DNS-01 TXT");
            cloudflare
                .create_txt(&t.name, &t.value, TTL_ACME_TXT)
                .await?;
        }
    }

    let zone = cloudflare.zone().await?;
    let nameservers = resolve_nameservers(&zone.name_servers).await?;
    wait_for_txt(
        challenge_name,
        &values,
        &nameservers,
        cfg.acme.propagation_poll,
        cfg.acme.propagation_timeout,
        clock,
    )
    .await?;
    Ok(())
}

async fn cleanup_challenge_txt(cloudflare: &CloudflareClient, name: &str) {
    match cloudflare.list_records(name, "TXT").await {
        Ok(recs) => {
            for r in recs {
                if let Err(e) = cloudflare.delete_record(&r.id).await {
                    warn!(id = %r.id, "best-effort delete of ACME TXT failed: {e}");
                }
            }
        }
        Err(e) => warn!("best-effort list of ACME TXT failed: {e}"),
    }
}
