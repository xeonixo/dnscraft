<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import LiveRegion from '$lib/components/LiveRegion.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import ShareBar from '$lib/components/ShareBar.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import StatusRow from '$lib/components/StatusRow.svelte';
	import CacheSheet from '$lib/dashboard/CacheSheet.svelte';
	import PauseSheet from '$lib/dashboard/PauseSheet.svelte';
	import * as view from '$lib/dashboard/view';
	import { settle, type Result } from '$lib/api/result';
	import {
		FILTER_SET,
		getCacheStats,
		getOverview,
		getReadiness,
		getStatus,
		getTopClients,
		getTopDomains,
		getUpstreams,
		type CacheStats,
		type FlushResult,
		type Period,
		type PauseDuration,
		type Readiness,
		type StatsOverview,
		type StatusData,
		type TopClient,
		type TopDomain,
		type Upstream,
		type UpstreamsData,
	} from '$lib/api/stats';
	import { auth } from '$lib/auth/state.svelte';
	import { announce } from '$lib/live.svelte';
	import { getLocale } from '$lib/i18n/locale';
	import {
		formatDateTime,
		formatFingerprint,
		formatMilliseconds,
		formatNumber,
		formatPercent,
		formatRelativeTime,
	} from '$lib/format';
	import { m } from '$lib/paraglide/messages';
	import { createPoller } from '$lib/poll';

	const locale = getLocale();
	const isAdmin = $derived(auth.role === 'admin');

	const POLL_INTERVAL_MS = 30_000;
	const POLL_MAX_BACKOFF_MS = 300_000;
	/** Rows shown per top list. */
	const TOP_LIMIT = 10;
	/** Domains fetched for both lists; the blocked ranking is computed from this window. */
	const DOMAIN_FETCH_LIMIT = 100;

	const periodOptions: { value: Period; label: string }[] = [
		{ value: '24h', label: m.period_24h() },
		{ value: '7d', label: m.period_7d() },
		{ value: '30d', label: m.period_30d() },
		{ value: '1y', label: m.period_1y() },
	];

	let period = $state<Period>('24h');
	let status = $state<Result<StatusData>>({ kind: 'loading' });
	let readiness = $state<Result<Readiness>>({ kind: 'loading' });
	let overview = $state<Result<StatsOverview>>({ kind: 'loading' });
	let domains = $state<Result<TopDomain[]>>({ kind: 'loading' });
	let clients = $state<Result<TopClient[]>>({ kind: 'loading' });
	let cache = $state<Result<CacheStats>>({ kind: 'loading' });
	let upstreams = $state<Result<UpstreamsData>>({ kind: 'loading' });

	/** The duration being confirmed; the sheet is mounted only while it is set. */
	let pauseDuration = $state<PauseDuration | null>(null);
	let cacheOpen = $state(false);

	/** One polling cycle reads every panel. Returns false when any read failed (triggers backoff). */
	async function refreshAll(): Promise<boolean> {
		const now = new Date();
		const current = period;
		const [s, r, o, d, c, k, u] = await Promise.all([
			settle(getStatus()),
			settle(getReadiness()),
			settle(getOverview(current, now)),
			settle(getTopDomains(current, DOMAIN_FETCH_LIMIT, now)),
			settle(getTopClients(current, TOP_LIMIT, now)),
			settle(getCacheStats(current, now)),
			settle(getUpstreams()),
		]);
		status = s;
		readiness = r;
		overview = o;
		domains = d;
		clients = c;
		cache = k;
		upstreams = u;
		return [s, r, o, d, c, k, u].every((result) => result.kind !== 'error');
	}

	const poller = createPoller(refreshAll, {
		intervalMs: POLL_INTERVAL_MS,
		maxBackoffMs: POLL_MAX_BACKOFF_MS,
		doc: globalThis.document,
	});

	onMount(() => {
		poller.start();
		return () => poller.stop();
	});

	/** Self-signed bootstrap: the names it is issued for and its fingerprint to pin. */
	const bootstrap = $derived.by(() => {
		if (status.kind !== 'ok' || status.data.tls_mode !== 'self_signed') return null;
		const names = status.data.tls?.identifiers ?? [];
		const fingerprint = status.data.tls_fingerprint ?? '';
		return {
			names: names.length > 0 ? names.join(', ') : '—',
			fingerprint: fingerprint === '' ? '' : formatFingerprint(fingerprint),
		};
	});

	const sourceRows = $derived(
		overview.kind === 'ok' ? view.answerSourceRows(overview.data.by_answer_source) : [],
	);

	const blockedDomains = $derived(
		domains.kind === 'ok' ? view.topBlockedDomains(domains.data, TOP_LIMIT) : [],
	);

	function upstreamDetails(item: Upstream): string[] {
		const lines = [item.protocol.toUpperCase()];
		lines.push(
			item.rtt_ms
				? m.dashboard_upstream_rtt({
						p50: formatMilliseconds(item.rtt_ms.p50, locale),
						p95: formatMilliseconds(item.rtt_ms.p95, locale),
					})
				: m.dashboard_no_sample(),
		);
		if (item.success_rate !== null) {
			lines.push(m.dashboard_upstream_success({ rate: formatPercent(item.success_rate, locale) }));
		}
		if (item.last_error) {
			lines.push(m.dashboard_upstream_last_error({ code: item.last_error.code }));
		}
		if (item.last_checked) {
			const time = formatRelativeTime(new Date(item.last_checked), new Date(), locale);
			lines.push(m.dashboard_upstream_last_checked({ time }));
		}
		return lines;
	}

	function onPaused(until: string): void {
		pauseDuration = null;
		announce(m.dashboard_pause_success({ time: formatDateTime(new Date(until), locale) }));
		poller.refresh();
	}

	function onFlushed(result: FlushResult): void {
		cacheOpen = false;
		const count = formatNumber(result.evicted, locale);
		announce(
			result.scope === 'all'
				? m.dashboard_cache_success_all({ count })
				: m.dashboard_cache_success_domain({ domain: result.domain ?? '', count }),
		);
		poller.refresh();
	}
</script>

{#if bootstrap}
	<Banner title={m.dashboard_selfsigned_title()}>
		<p>{m.dashboard_selfsigned_body({ names: bootstrap.names })}</p>
		{#if bootstrap.fingerprint !== ''}
			<p class="fingerprint">
				<span>{m.dashboard_fingerprint_label()}</span>
				<code>{bootstrap.fingerprint}</code>
			</p>
		{/if}
		<p><a href={resolve('/tls')}>{m.dashboard_tls_link()}</a></p>
	</Banner>
{/if}

{#if isAdmin}
	<GroupedList header={m.dashboard_section_actions()}>
		<GroupedRow
			label={m.dashboard_pause_row_label()}
			detail={m.dashboard_pause_row_detail({ set: FILTER_SET })}
		>
			{#snippet trailing()}
				<div class="inline-actions">
					<Button
						aria-label={m.dashboard_pause_title({ duration: m.dashboard_duration_5m() })}
						onclick={() => (pauseDuration = 'PT5M')}>{m.dashboard_pause_5m()}</Button
					>
					<Button
						aria-label={m.dashboard_pause_title({ duration: m.dashboard_duration_1h() })}
						onclick={() => (pauseDuration = 'PT1H')}>{m.dashboard_pause_1h()}</Button
					>
				</div>
			{/snippet}
		</GroupedRow>
	</GroupedList>
{/if}

<div class="filter-row">
	<Segmented
		options={periodOptions}
		bind:value={period}
		label={m.dashboard_period_label()}
		onchange={() => poller.refresh()}
	/>
</div>

{#if overview.kind === 'ok'}
	<div class="tiles">
		<StatTile label={m.dashboard_tile_total()} value={formatNumber(overview.data.total, locale)} />
		<StatTile
			label={m.dashboard_tile_allowed()}
			value={formatNumber(overview.data.allowed, locale)}
			tone="ok"
			toneLabel={m.dashboard_share_of_total({
				ratio: formatPercent(view.shareOf(overview.data.allowed, overview.data.total), locale),
			})}
		/>
		<StatTile
			label={m.dashboard_tile_blocked()}
			value={formatNumber(overview.data.blocked, locale)}
			tone="danger"
			toneLabel={m.dashboard_share_of_total({
				ratio: formatPercent(view.shareOf(overview.data.blocked, overview.data.total), locale),
			})}
		/>
		<StatTile
			label={m.dashboard_tile_blocked_share()}
			value={formatPercent(view.shareOf(overview.data.blocked, overview.data.total), locale)}
		/>
	</div>
	{#if overview.data.source === 'rollup'}
		<p class="note">{m.dashboard_retention_note()}</p>
	{/if}
{:else}
	<ResultNotice result={overview} onretry={() => poller.refresh()} />
{/if}

{#if overview.kind === 'ok'}
	<GroupedList header={m.dashboard_section_sources()} footer={m.dashboard_sources_footer()}>
		{#each sourceRows as row (row.source)}
			<GroupedRow
				label={view.answerSourceLabel(row.source)}
				detail={formatPercent(row.share, locale)}
			>
				{#snippet trailing()}
					<span class="trail">
						<ShareBar share={row.share} />
						<span class="num">{formatNumber(row.count, locale)}</span>
					</span>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.dashboard_empty_period()} />
		{/each}
	</GroupedList>
{/if}

{#if upstreams.kind === 'ok'}
	<GroupedList
		header={m.dashboard_section_upstreams()}
		footer={m.dashboard_upstreams_footer({
			minutes: formatNumber(Math.round(upstreams.data.window_seconds / 60), locale),
		})}
	>
		{#each upstreams.data.items as item, index (index)}
			{@const verdict = view.upstreamVerdict(item.state)}
			<StatusRow
				icon={verdict.icon}
				tone={verdict.tone}
				label={item.kind === 'recursion' ? m.dashboard_recursion() : item.name}
				mono={item.kind !== 'recursion'}
				details={upstreamDetails(item)}
				verdict={verdict.label}
			/>
		{/each}
	</GroupedList>
{:else}
	<ResultNotice result={upstreams} onretry={() => poller.refresh()} />
{/if}

{#if cache.kind !== 'ok'}
	<ResultNotice result={cache} onretry={() => poller.refresh()} />
{/if}
<GroupedList header={m.dashboard_section_cache()}>
	{#if cache.kind === 'ok'}
		{@const stats = cache.data}
		<GroupedRow
			label={m.dashboard_cache_hit_ratio()}
			detail={m.dashboard_cache_detail({
				hits: formatNumber(stats.hits, locale),
				misses: formatNumber(stats.misses, locale),
			})}
		>
			{#snippet trailing()}
				<span class="num">{formatPercent(stats.hit_ratio, locale)}</span>
			{/snippet}
		</GroupedRow>
	{/if}
	{#if isAdmin}
		<GroupedRow label={m.dashboard_cache_clear()} detail={m.dashboard_cache_clear_detail()}>
			{#snippet trailing()}
				<Button onclick={() => (cacheOpen = true)}>{m.dashboard_cache_clear()}</Button>
			{/snippet}
		</GroupedRow>
	{/if}
</GroupedList>

{#if status.kind === 'ok'}
	{@const data = status.data}
	<GroupedList
		header={m.dashboard_section_modules()}
		footer={m.dashboard_version({ version: data.version })}
	>
		{#if readiness.kind === 'ok'}
			{@const ready = view.readinessVerdict(readiness.data.ready)}
			<StatusRow
				icon={ready.icon}
				tone={ready.tone}
				label={m.dashboard_node_label()}
				details={[
					ready.tone === 'ok' ? m.dashboard_node_ready() : m.dashboard_node_not_ready(),
				].concat(
					data.modules_not_ready.length > 0
						? [m.dashboard_modules_pending({ modules: data.modules_not_ready.join(', ') })]
						: [],
				)}
				verdict={ready.label}
			/>
		{:else}
			{@const unknown = view.unknownVerdict()}
			<StatusRow
				icon={unknown.icon}
				tone={unknown.tone}
				label={m.dashboard_node_label()}
				details={[view.resultText(readiness)]}
				verdict={unknown.label}
			/>
		{/if}
		{#if data.tls_mode}
			{@const tls = view.tlsVerdict(data.tls_mode)}
			<StatusRow
				icon={tls.icon}
				tone={tls.tone}
				label={m.dashboard_tls_label()}
				details={[view.tlsModeLabel(data.tls_mode)]}
				verdict={tls.label}
			/>
		{/if}
	</GroupedList>
{:else}
	<ResultNotice result={status} onretry={() => poller.refresh()} />
{/if}

{#if domains.kind === 'ok'}
	<GroupedList header={m.dashboard_section_top_domains()}>
		{#each domains.data.slice(0, TOP_LIMIT) as row, index (index)}
			<GroupedRow
				label={row.domain}
				mono
				detail={m.dashboard_count_blocked({ count: formatNumber(row.blocked, locale) })}
			>
				{#snippet trailing()}
					<span class="num">{formatNumber(row.queries, locale)}</span>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.dashboard_empty_period()} />
		{/each}
	</GroupedList>

	<GroupedList header={m.dashboard_section_top_blocked()}>
		{#each blockedDomains as row, index (index)}
			<GroupedRow
				label={row.domain}
				mono
				detail={m.dashboard_count_queries({ count: formatNumber(row.queries, locale) })}
			>
				{#snippet trailing()}
					<span class="num">{formatNumber(row.blocked, locale)}</span>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.dashboard_nothing_blocked()} />
		{/each}
	</GroupedList>
{:else}
	<ResultNotice result={domains} onretry={() => poller.refresh()} />
{/if}

{#if clients.kind === 'ok'}
	<GroupedList header={m.dashboard_section_top_clients()}>
		{#each clients.data as row, index (index)}
			<GroupedRow
				label={row.client_name !== '' ? row.client_name : row.client_id}
				mono={row.client_name === ''}
				detail={m.dashboard_count_blocked({ count: formatNumber(row.blocked, locale) })}
			>
				{#snippet trailing()}
					<span class="num">{formatNumber(row.queries, locale)}</span>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.dashboard_empty_period()} />
		{/each}
	</GroupedList>
{:else}
	<ResultNotice result={clients} onretry={() => poller.refresh()} />
{/if}

{#if pauseDuration !== null}
	<PauseSheet duration={pauseDuration} onclose={() => (pauseDuration = null)} onpaused={onPaused} />
{/if}

{#if cacheOpen}
	<CacheSheet onclose={() => (cacheOpen = false)} onflushed={onFlushed} />
{/if}

<LiveRegion />

<style>
	.inline-actions,
	.trail {
		display: flex;
		align-items: center;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.5rem;
	}

	.filter-row {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.625rem;
	}

	.tiles {
		display: grid;
		grid-template-columns: repeat(4, minmax(0, 1fr));
		gap: 0.75rem;
	}

	.num {
		font-variant-numeric: tabular-nums;
		font-weight: 600;
	}

	.note {
		margin: 0;
		padding: 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.fingerprint {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem;
		margin: 0.5rem 0 0;
		font-size: 0.8125rem;
	}

	.fingerprint code {
		display: inline-block;
		max-width: 100%;
		padding: 0.25rem 0.5rem;
		background: var(--surface-2);
		border-radius: var(--r-ctl);
		font-family: var(--font-mono);
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	a {
		display: inline-flex;
		align-items: center;
		min-height: 2.75rem;
		color: var(--accent);
		text-decoration: none;
	}

	a:hover {
		text-decoration: underline;
	}

	@media (max-width: 47.99rem) {
		.tiles {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}

	@media (max-width: 32.49rem) {
		.tiles {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
