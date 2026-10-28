//! ACME DNS-01 issuance orchestration.
//!
//! Publishes Cloudflare TXT records, waits for authoritative propagation,
//! finalizes the order, stores and installs the certificate, then cleans up
//! challenge records.

use std::time::SystemTime;

use tracing::{debug, info, warn};

use rustls_pki_types::CertificateSigningRequestDer;
use rustls_pki_types::pem::PemObject;

use crate::acme::{
    AcmeDirectory, AcmeOrder, Dns01Txt, challenge_txt_name, csr_dns_names, default_identifiers,
};
use crate::clock::Clock;
use crate::cloudflare::{CloudflareClient, TTL_ACME_TXT};
use crate::config::{DnsProviderKind, ManualDns01Config, TlsConfig};
use crate::error::TlsError;
use crate::propagation::{resolve_nameservers, wait_for_txt};
use crate::resolver::CertResolver;
use crate::status::{CertSource, IssueOutcome, IssueRecord};
use crate::store::{CertMeta, CertStore, push_history};

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
    let had_cert = store.load().ok().flatten().is_some();
    let result = issue_inner(acme, cloudflare, store, resolver, cfg, clock).await;

    let mut state = store.load_state();
    state.last_renew_attempt_unix = Some(unix_secs(attempted));
    let record = match &result {
        Ok(()) => {
            state.last_error = None;
            state.last_issue_unix = Some(unix_secs(clock.now()));
            state.revoked = false;
            state.revoked_reason = None;
            let serial = store.load().ok().flatten().and_then(|c| c.detail.serial);
            IssueRecord {
                timestamp: attempted,
                outcome: if had_cert {
                    IssueOutcome::Renewed
                } else {
                    IssueOutcome::Issued
                },
                error: None,
                serial,
            }
        }
        Err(e) => {
            state.last_error = Some(e.code().to_owned());
            IssueRecord {
                timestamp: attempted,
                outcome: IssueOutcome::Failed,
                error: Some(e.code().to_owned()),
                serial: None,
            }
        }
    };
    push_history(&mut state, record);
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
    let identifiers = default_identifiers(&cfg.public_domain);

    // Renewal: tell the CA which certificate this order replaces (ARI).
    let replaces = store.load().ok().flatten().and_then(|c| {
        c.meta
            .ari_cert_id
            .or_else(|| acme.certificate_id(&c.chain_pem))
    });

    let (chain_pem, key_pem) = order_dns01(
        acme,
        cloudflare,
        store,
        cfg,
        &identifiers,
        replaces.as_deref(),
        None,
        clock,
    )
    .await?;

    // Persist + install only after a complete chain; failure here keeps the
    // previous cert (store.save validates before writing).
    let meta = CertMeta {
        identifiers: identifiers.to_vec(),
        ari_cert_id: acme.certificate_id(&chain_pem),
        source: CertSource::Acme,
        ..CertMeta::default()
    };
    store.save(&chain_pem, &key_pem, &meta)?;
    if let Err(e) = resolver.install(&chain_pem, &key_pem) {
        // Disk has the new cert; try to keep resolver in sync — if install
        // fails the previous in-memory cert remains (install is atomic swap).
        warn!("issued cert saved but resolver install failed: {e}");
        return Err(e);
    }

    info!(
        domain = %cfg.public_domain,
        "issued and installed TLS certificate"
    );
    Ok(())
}

/// Signs a node's CSR for the public names (DNS-01) and returns the chain PEM.
///
/// The key stays with the caller: the order is finalized with `csr_pem` only.
/// The request may name only `dns.<domain>` / `*.dns.<domain>`. Nothing in
/// `store` or the resolver changes, so the master's own certificate is kept.
/// Same preflight, rate-limit and order status handling as [`issue`].
pub async fn sign_csr<A>(
    acme: &A,
    cloudflare: &CloudflareClient,
    store: &CertStore,
    cfg: &TlsConfig,
    csr_pem: &str,
    clock: &dyn Clock,
) -> Result<String, TlsError>
where
    A: AcmeDirectory + AcmeOrder + ?Sized,
{
    if !cfg.acme.enabled {
        return Err(TlsError::config("ACME is disabled"));
    }
    let csr_der =
        CertificateSigningRequestDer::from_pem_slice(csr_pem.as_bytes()).map_err(|e| {
            TlsError::AcmeOrder {
                message: format!("CSR PEM: {e}"),
            }
        })?;
    let names = csr_dns_names(csr_der.as_ref())?;
    let allowed = default_identifiers(&cfg.public_domain);
    if names.iter().any(|n| !allowed.contains(n)) {
        return Err(TlsError::AcmeOrder {
            message: "CSR requests a name outside the configured public names".into(),
        });
    }
    let (chain, _key) = order_dns01(
        acme,
        cloudflare,
        store,
        cfg,
        &names,
        None,
        Some(csr_der.as_ref()),
        clock,
    )
    .await?;
    String::from_utf8(chain).map_err(|_| TlsError::AcmeOrder {
        message: "certificate chain is not UTF-8".into(),
    })
}

/// One DNS-01 order: ensure the account, publish the challenge TXT records,
/// wait for propagation, then finalize (generated key, or the caller's CSR).
/// Challenge TXT records are removed on every exit path. Returns
/// `(chain_pem, key_pem)`; the key is empty for a CSR order.
#[allow(clippy::too_many_arguments)]
async fn order_dns01<A>(
    acme: &A,
    cloudflare: &CloudflareClient,
    store: &CertStore,
    cfg: &TlsConfig,
    identifiers: &[String],
    replaces: Option<&str>,
    csr_der: Option<&[u8]>,
    clock: &dyn Clock,
) -> Result<(Vec<u8>, Vec<u8>), TlsError>
where
    A: AcmeDirectory + AcmeOrder + ?Sized,
{
    acme.ensure_account(store, &cfg.acme).await?;

    let challenge_name = challenge_txt_name(&default_identifiers(&cfg.public_domain)[0]);

    // Orphan cleanup: drop any leftover `_acme-challenge` TXT from a prior run.
    cleanup_if_cloudflare(cfg, cloudflare, &challenge_name).await;

    let txts = match acme
        .start_dns01_order(store, &cfg.acme, identifiers, replaces)
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
        cleanup_if_cloudflare(cfg, cloudflare, &challenge_name).await;
        return Err(e);
    }

    let finished = match csr_der {
        Some(der) => acme
            .finish_dns01_order_csr(der)
            .await
            .map(|chain| (chain, Vec::new())),
        None => acme.finish_dns01_order(cfg.key_type).await,
    };
    match finished {
        Ok(pair) => {
            cleanup_if_cloudflare(cfg, cloudflare, &challenge_name).await;
            Ok(pair)
        }
        Err(e) => {
            acme.abort_order().await;
            let _guard = cloudflare.write_guard().await;
            cleanup_challenge_txt(cloudflare, &challenge_name).await;
            Err(e)
        }
    }
}

async fn publish_and_wait(
    cloudflare: &CloudflareClient,
    txts: &[Dns01Txt],
    challenge_name: &str,
    cfg: &TlsConfig,
    clock: &dyn Clock,
) -> Result<(), TlsError> {
    match cfg.dns_provider.kind {
        DnsProviderKind::Cloudflare => {
            publish_cloudflare(cloudflare, txts, challenge_name, cfg, clock).await
        }
        DnsProviderKind::Manual => publish_manual(&cfg.dns_provider.manual_txt, txts),
        DnsProviderKind::None => Err(TlsError::DnsProviderAuth {
            message: "dns_provider.kind = none cannot publish ACME DNS-01 records".into(),
        }),
    }
}

async fn publish_cloudflare(
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

    let zone = cloudflare.zone_for_name(challenge_name).await?;
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

/// Manual DNS-01: each challenge TXT value must be pre-published by the operator.
///
/// The order carries one value per identifier but apex + wildcard share an
/// owner, so `configured` is a list with one entry per value.
fn publish_manual(configured: &[ManualDns01Config], txts: &[Dns01Txt]) -> Result<(), TlsError> {
    let covered = txts.iter().all(|t| {
        configured
            .iter()
            .any(|cfg| t.name.eq_ignore_ascii_case(&cfg.name) && t.value == cfg.value)
    });
    if covered {
        return Ok(());
    }
    let required = txts
        .iter()
        .map(|t| format!("{} {}", t.name, t.value))
        .collect::<Vec<_>>()
        .join("; ");
    Err(TlsError::DnsManual {
        message: format!(
            "publish the challenge TXT record(s) and set dns_provider.manual_txt: {required}"
        ),
    })
}

async fn cleanup_if_cloudflare(cfg: &TlsConfig, cloudflare: &CloudflareClient, name: &str) {
    if !cfg.dns_provider.uses_cloudflare() {
        return;
    }
    let _guard = cloudflare.write_guard().await;
    cleanup_challenge_txt(cloudflare, name).await;
}

async fn cleanup_challenge_txt(cloudflare: &CloudflareClient, name: &str) {
    let zone = match cloudflare.zone_for_name(name).await {
        Ok(zone) => zone,
        Err(e) => {
            warn!(
                code = e.code(),
                "best-effort zone lookup for ACME TXT failed: {e}"
            );
            return;
        }
    };
    match cloudflare.list_records(name, "TXT").await {
        Ok(recs) => {
            for r in recs {
                if let Err(e) = cloudflare.delete_record_in(&zone.id, &r.id).await {
                    warn!(id = %r.id, "best-effort delete of ACME TXT failed: {e}");
                }
            }
        }
        Err(e) => warn!("best-effort list of ACME TXT failed: {e}"),
    }
}
