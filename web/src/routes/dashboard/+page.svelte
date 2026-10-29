<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import StatTile from '$lib/components/StatTile.svelte';
	import StatusRow from '$lib/components/StatusRow.svelte';
	import CacheSheet from '$lib/dashboard/CacheSheet.svelte';
	import PauseSheet from '$lib/dashboard/PauseSheet.svelte';
	import * as view from '$lib/dashboard/view';
	import { listClusterNodes, type ClusterNode } from '$lib/api/cluster';
	import { nodeLag, nodeRoleLabel, nodeStatusLabel, nodeVerdict } from '$lib/cluster/nodes';
	import { listAllMcpRules, resumeFilterSet } from '$lib/api/mcp-rules';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import {
		getCacheStats,
		getOverview,
		getReadiness,
		getStatus,
		getTopClients,
		getTopDomains,
		FILTER_SET,
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
	import { displayText } from '$lib/safe-text';

	const locale = getLocale();
	const isAdmin = $derived(auth.role === 'admin');

	/** Shown for a value whose read has not produced data. */
	const NO_VALUE = '—';
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
	/** Registry rows for the cluster card; a failed read leaves the list empty. */
	let clusterNodes = $state<ClusterNode[]>([]);

	/** The duration being confirmed; the sheet is mounted only while it is set. */
	let pauseDuration = $state<PauseDuration | null>(null);
	let cacheOpen = $state(false);
	/** End of a running pause on the default filter set (RFC 3339), or null. */
	let pausedUntil = $state<string | null>(null);
	let clock = $state(Date.now());
	let resumeBusy = $state(false);
	let resumeFailure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	const pauseRemainingMs = $derived(pausedUntil ? Date.parse(pausedUntil) - clock : 0);
	const paused = $derived(pausedUntil !== null && pauseRemainingMs > 0);

	/** Reads a pause that is already running (set elsewhere or before a reload); a failure shows no banner. */
	async function loadPause(): Promise<void> {
		try {
			const rows = await listAllMcpRules('pauses', FILTER_SET);
			const live = rows
				.map((row) => row.paused_until ?? '')
				.filter((instant) => Date.parse(instant) > Date.now())
				.sort();
			pausedUntil = live.at(-1) ?? null;
		} catch {
			// no banner
		}
	}

	async function resume(): Promise<void> {
		resumeBusy = true;
		resumeFailure = null;
		try {
			await resumeFilterSet(FILTER_SET);
			pausedUntil = null;
			announce(m.dashboard_resumed());
			poller.refresh();
		} catch (cause) {
			resumeFailure = failureOf(cause);
		} finally {
			resumeBusy = false;
		}
	}

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
		void loadPause();
		const tick = setInterval(() => (clock = Date.now()), 15_000);
		void settle(listClusterNodes()).then((result) => {
			if (result.kind === 'ok') clusterNodes = result.data;
		});
		return () => {
			poller.stop();
			clearInterval(tick);
		};
	});

	/** Each non-revoked node with its config lag, in registry order. */
	const clusterRows = $derived.by(() => {
		const lags = nodeLag(clusterNodes);
		return clusterNodes
			.map((node, index) => ({ node, lag: lags[index] ?? 0 }))
			.filter((row) => !row.node.revoked);
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

	const totals = $derived(overview.kind === 'ok' ? overview.data : null);
	const blockRate = $derived(totals ? view.shareOf(totals.blocked, totals.total) : 0);
	const sourceRows = $derived(
		overview.kind === 'ok' ? view.answerSourceRows(overview.data.by_answer_source) : [],
	);

	const topDomainRows = $derived(domains.kind === 'ok' ? domains.data.slice(0, TOP_LIMIT) : []);
	const blockedDomains = $derived(
		domains.kind === 'ok' ? view.topBlockedDomains(domains.data, TOP_LIMIT) : [],
	);
	const clientRows = $derived(clients.kind === 'ok' ? clients.data : []);

	/** Largest value in each list, so the proportional bars share one scale per list. */
	const maxOf = (values: number[]): number =>
		values.reduce((top, value) => Math.max(top, value), 0);
	const maxDomainQueries = $derived(maxOf(topDomainRows.map((row) => row.queries)));
	const maxBlocked = $derived(maxOf(blockedDomains.map((row) => row.blocked)));
	const maxClientQueries = $derived(maxOf(clientRows.map((row) => row.queries)));

	const healthId = $props.id();
	const problems = $derived(
		view.healthProblems({
			ready: readiness.kind === 'ok' ? readiness.data.ready : null,
			modulesNotReady: status.kind === 'ok' ? status.data.modules_not_ready : [],
			tlsMode: status.kind === 'ok' ? (status.data.tls_mode ?? null) : null,
			upstreams: upstreams.kind === 'ok' ? upstreams.data.items : [],
		}),
	);
	/** True only when every read behind the strip has data, so 'All OK' is never shown on a guess. */
	const healthKnown = $derived(
		status.kind === 'ok' && readiness.kind === 'ok' && upstreams.kind === 'ok',
	);
	const healthTone = $derived(problems.length > 0 ? 'warn' : healthKnown ? 'ok' : 'neutral');
	const healthIcon = $derived(
		problems.length > 0 ? 'alert-triangle' : healthKnown ? 'check-circle' : 'help-circle',
	);

	const upstreamSplit = $derived(
		view.splitUpstreams(upstreams.kind === 'ok' ? upstreams.data.items : []),
	);
	const upstreamsFooter = $derived(
		upstreams.kind === 'ok'
			? m.dashboard_upstreams_footer({
					minutes: formatNumber(Math.round(upstreams.data.window_seconds / 60), locale),
				})
			: undefined,
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
		// A success rate without samples is not a measurement; it is hidden until one exists.
		if (item.samples > 0 && item.success_rate !== null) {
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
		pausedUntil = until;
		clock = Date.now();
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

{#snippet nodeIcon(node: ClusterNode, lag: number)}
	{@const verdict = nodeVerdict(node, lag)}
	<span class="symbol {verdict.tone}"
		><Icon name={verdict.icon} size="1.125rem" strokeWidth={1.7} /></span
	>
{/snippet}

{#snippet upstreamRow(item: Upstream)}
	{@const verdict = view.upstreamVerdict(item.state)}
	<StatusRow
		icon={verdict.icon}
		tone={verdict.tone}
		label={item.kind === 'recursion' ? m.dashboard_recursion() : item.name}
		mono={item.kind !== 'recursion'}
		details={upstreamDetails(item)}
		verdict={verdict.label}
	/>
{/snippet}

<div class="dash">
	{#if paused && pausedUntil}
		<Banner title={m.dashboard_paused_title()}>
			<p>
				{m.dashboard_paused_body({
					time: formatDateTime(new Date(pausedUntil), locale),
					minutes: formatNumber(Math.max(1, Math.ceil(pauseRemainingMs / 60_000)), locale),
				})}
			</p>
			{#if isAdmin}
				<p>
					<Button variant="primary" disabled={resumeBusy} onclick={() => void resume()}>
						{m.dashboard_resume()}
					</Button>
				</p>
			{/if}
			{#if resumeFailure}<ErrorNotice
					code={resumeFailure.code}
					params={resumeFailure.params}
				/>{/if}
		</Banner>
	{/if}
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

	<header class="page-head">
		{#if isAdmin}
			<div class="pause">
				<span class="pause-label">{m.dashboard_pause_row_label()}</span>
				<Button
					aria-label={m.dashboard_pause_title({ duration: m.dashboard_duration_5m() })}
					onclick={() => (pauseDuration = 'PT5M')}>{m.dashboard_pause_5m()}</Button
				>
				<Button
					aria-label={m.dashboard_pause_title({ duration: m.dashboard_duration_1h() })}
					onclick={() => (pauseDuration = 'PT1H')}>{m.dashboard_pause_1h()}</Button
				>
			</div>
		{/if}
		<Segmented
			options={periodOptions}
			bind:value={period}
			label={m.dashboard_period_label()}
			onchange={() => poller.refresh()}
		/>
	</header>

	<section class="health {healthTone}" aria-labelledby={healthId}>
		<span class="symbol"><Icon name={healthIcon} size="1.125rem" strokeWidth={1.7} /></span>
		<h2 class="health-title" id={healthId}>
			{#if problems.length === 0}
				{healthKnown ? m.dashboard_health_ok() : m.status_unknown()}
			{:else if problems.length === 1}
				{m.dashboard_health_one()}
			{:else}
				{m.dashboard_health_many({ count: formatNumber(problems.length, locale) })}
			{/if}
		</h2>
		{#if problems.length > 0}
			<ul class="problems">
				{#each problems as problem, index (index)}
					<li>
						{problem.label}: {problem.verdict}{#if problem.detail}<span class="detail">
								· {problem.detail}</span
							>{/if}
					</li>
				{/each}
			</ul>
		{/if}
		{#if upstreams.kind === 'ok' && upstreamSplit.healthy.length > 0 && upstreamSplit.affected.length === 0}
			<p class="summary">
				{m.dashboard_upstreams_healthy({
					count: formatNumber(upstreamSplit.healthy.length, locale),
				})}
			</p>
		{/if}
	</section>
	{#if status.kind !== 'ok'}
		<ResultNotice result={status} onretry={() => poller.refresh()} />
	{/if}

	{#if status.kind === 'ok' && status.data.cluster}
		{@const cluster = status.data.cluster}
		<GroupedList header={m.dashboard_cluster_header()}>
			<GroupedRow label={m.dashboard_cluster_role()} detail={nodeRoleLabel(cluster.role)} />
			<GroupedRow label={m.dashboard_cluster_lag()}>
				{#snippet trailing()}
					<span class="num">{m.sidebar_node_lag({ lag: formatNumber(cluster.lag, locale) })}</span>
				{/snippet}
			</GroupedRow>
			<GroupedRow label={m.dashboard_cluster_degraded()}>
				{#snippet trailing()}
					<span class="num">{formatNumber(cluster.degraded_nodes, locale)}</span>
				{/snippet}
			</GroupedRow>
			{#each clusterRows as { node, lag } (node.node_id)}
				<GroupedRow
					label={displayText(node.node_id).text}
					mono
					truncate
					detail={`${nodeRoleLabel(node.role)} · ${nodeStatusLabel(node, lag, locale)}`}
					href="/cluster"
				>
					{#snippet leading()}
						{@render nodeIcon(node, lag)}
					{/snippet}
				</GroupedRow>
			{/each}
			<GroupedRow label={m.dashboard_cluster_open()} href="/cluster" />
		</GroupedList>
	{/if}

	<div class="tiles">
		<StatTile
			label={m.dashboard_tile_total()}
			value={totals ? formatNumber(totals.total, locale) : NO_VALUE}
		/>
		<StatTile
			label={m.dashboard_tile_allowed()}
			value={totals ? formatNumber(totals.allowed, locale) : NO_VALUE}
		/>
		<StatTile
			label={m.dashboard_tile_blocked()}
			value={totals ? formatNumber(totals.blocked, locale) : NO_VALUE}
			tone={totals ? 'danger' : undefined}
			toneLabel={totals
				? m.dashboard_share_of_total({ ratio: formatPercent(blockRate, locale) })
				: undefined}
		/>
	</div>
	{#if totals?.source === 'rollup'}
		<p class="note">{m.dashboard_retention_note()}</p>
	{/if}

	<div class="grid">
		<div class="cell">
			{#if overview.kind === 'ok'}
				<GroupedList header={m.dashboard_section_sources()} footer={m.dashboard_sources_footer()}>
					<div class="sources">
						{#if sourceRows.length > 0}
							<div class="stack" aria-hidden="true">
								{#each sourceRows as row (row.source)}
									<span
										class="seg fill-{view.answerSourceTone(row.source)}"
										style:width="{row.share * 100}%"
									></span>
								{/each}
							</div>
							<ul class="legend">
								{#each sourceRows as row (row.source)}
									<li>
										<span class="swatch fill-{view.answerSourceTone(row.source)}" aria-hidden="true"
										></span>
										<span class="name">{view.answerSourceLabel(row.source)}</span>
										<span class="num">{formatNumber(row.count, locale)}</span>
										<span class="pct">{formatPercent(row.share, locale)}</span>
									</li>
								{/each}
							</ul>
						{:else}
							<p class="empty">{m.dashboard_empty_period()}</p>
						{/if}
					</div>
				</GroupedList>
			{:else}
				<ResultNotice result={overview} onretry={() => poller.refresh()} />
			{/if}
		</div>

		<div class="cell">
			{#if upstreams.kind === 'ok' && upstreamSplit.affected.length > 0}
				<GroupedList header={m.dashboard_section_upstreams()} footer={upstreamsFooter}>
					{#each upstreamSplit.affected as item, index (index)}
						{@render upstreamRow(item)}
					{/each}
					{#if upstreamSplit.healthy.length > 0}
						<details class="disclosure fold">
							<summary>
								{m.dashboard_upstreams_more_ok({
									count: formatNumber(upstreamSplit.healthy.length, locale),
								})}
							</summary>
							<div class="rows">
								{#each upstreamSplit.healthy as item, index (index)}
									{@render upstreamRow(item)}
								{/each}
							</div>
						</details>
					{/if}
				</GroupedList>
			{:else if upstreams.kind === 'ok' && upstreams.data.items.length > 0}
				<details class="disclosure card">
					<summary>{m.dashboard_upstream_details()}</summary>
					<div class="rows">
						{#each upstreams.data.items as item, index (index)}
							{@render upstreamRow(item)}
						{/each}
					</div>
					<p class="foot">{upstreamsFooter}</p>
				</details>
			{:else if upstreams.kind !== 'ok'}
				<ResultNotice result={upstreams} onretry={() => poller.refresh()} />
			{/if}
		</div>

		{#if domains.kind === 'ok'}
			<div class="cell">
				<GroupedList header={m.dashboard_section_top_domains()}>
					{#each topDomainRows as row, index (index)}
						{@const shown = displayText(row.domain)}
						<GroupedRow
							label={shown.text}
							mono
							truncate
							share={view.shareOf(row.queries, maxDomainQueries)}
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
			</div>

			<div class="cell">
				<GroupedList header={m.dashboard_section_top_blocked()}>
					{#each blockedDomains as row, index (index)}
						{@const shown = displayText(row.domain)}
						<GroupedRow
							label={shown.text}
							mono
							truncate
							share={view.shareOf(row.blocked, maxBlocked)}
							shareTone="danger"
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
			</div>
		{:else}
			<div class="cell wide">
				<ResultNotice result={domains} onretry={() => poller.refresh()} />
			</div>
		{/if}

		<div class="cell">
			{#if clients.kind === 'ok'}
				<GroupedList header={m.dashboard_section_top_clients()}>
					{#each clients.data as row, index (index)}
						{@const shown = displayText(row.client_name !== '' ? row.client_name : row.client_id)}
						<GroupedRow
							label={shown.text}
							mono={row.client_name === ''}
							truncate
							share={view.shareOf(row.queries, maxClientQueries)}
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
		</div>

		<div class="cell">
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
			</GroupedList>
			{#if isAdmin}
				<div class="cache-actions">
					<Button aria-label={m.dashboard_cache_clear()} onclick={() => (cacheOpen = true)}
						>{m.dashboard_cache_clear_short()}</Button
					>
				</div>
			{/if}
		</div>
	</div>

	{#if status.kind === 'ok'}
		<p class="version">{m.dashboard_version({ version: status.data.version })}</p>
	{/if}
</div>

{#if pauseDuration !== null}
	<PauseSheet duration={pauseDuration} onclose={() => (pauseDuration = null)} onpaused={onPaused} />
{/if}

{#if cacheOpen}
	<CacheSheet onclose={() => (cacheOpen = false)} onflushed={onFlushed} />
{/if}

<style>
	.dash {
		display: flex;
		flex-direction: column;
		gap: 1.125rem;
		container: dash / inline-size;
	}

	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.625rem;
	}

	.pause {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem;
		margin-inline-end: auto;
	}

	.pause-label {
		font-size: 0.875rem;
		font-weight: 600;
	}

	.health {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		gap: 0.5rem 0.75rem;
		padding: 0.875rem 1rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
	}

	.health .symbol {
		display: inline-flex;
		padding-top: 0.125rem;
	}

	.health-title {
		margin: 0;
		font-size: 1rem;
		font-weight: 600;
		color: var(--label);
	}

	.problems,
	.summary {
		display: flex;
		flex: 1 1 100%;
		flex-wrap: wrap;
		gap: 0.25rem 1rem;
		margin: 0;
		padding: 0 0 0 1.875rem;
		list-style: none;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.health .detail {
		color: var(--label-3);
	}

	.symbol {
		display: inline-flex;
		flex: 0 0 auto;
	}

	.symbol.ok {
		color: var(--ok);
	}

	.symbol.warn {
		color: var(--warn);
	}

	.symbol.neutral {
		color: var(--label-3);
	}

	.health.warn .symbol {
		color: var(--warn);
	}

	.health.ok .symbol {
		color: var(--ok);
	}

	.health.neutral .symbol {
		color: var(--label-3);
	}

	.tiles {
		display: grid;
		grid-template-columns: repeat(3, minmax(0, 1fr));
		gap: 0.75rem;
	}

	/* Healthy upstreams fold into a disclosure: the latency numbers are detail, not status. */
	.disclosure > summary {
		display: flex;
		align-items: center;
		min-height: 2.75rem;
		padding: 0.5rem 1rem;
		font-size: 0.9375rem;
		font-weight: 500;
		color: var(--accent);
		cursor: pointer;
	}

	.disclosure.card {
		overflow: hidden;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow);
	}

	.disclosure .rows {
		border-top: 1px solid var(--separator);
	}

	.disclosure .rows > :global(* + *) {
		border-top: 1px solid var(--separator);
	}

	.disclosure .foot {
		margin: 0;
		padding: 0.5rem 1rem 0.75rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	/* The cache clear action is a quiet text button, not a card row. */
	.cache-actions {
		display: flex;
		justify-content: flex-end;
	}

	.cache-actions :global(.btn) {
		background: transparent;
		border-color: transparent;
		color: var(--accent);
		font-weight: 500;
	}

	.grid {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: 1.125rem;
		align-items: start;
	}

	.cell {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		min-width: 0;
	}

	.wide {
		grid-column: 1 / -1;
	}

	/* Section headings carry the hierarchy on this page: larger and higher contrast than the shared default. */
	.dash :global(.head) {
		font-size: 1.0625rem;
		font-weight: 600;
		letter-spacing: -0.01em;
		color: var(--label);
	}

	.sources {
		display: flex;
		flex-direction: column;
		gap: 0.75rem;
		padding: 0.875rem 1rem;
	}

	.stack {
		display: flex;
		height: 0.75rem;
		overflow: hidden;
		background: var(--surface-2);
		border-radius: var(--r-ctl);
	}

	.seg {
		flex: 0 0 auto;
		height: 100%;
	}

	.legend {
		display: grid;
		gap: 0.125rem;
		margin: 0;
		padding: 0;
		list-style: none;
	}

	.legend li {
		display: grid;
		grid-template-columns: auto minmax(0, 1fr) auto 3.5rem;
		align-items: center;
		gap: 0.625rem;
		min-height: 2.25rem;
		font-size: 0.9375rem;
	}

	.swatch {
		display: block;
		width: 0.75rem;
		height: 0.75rem;
		border-radius: 0.1875rem;
	}

	.name {
		overflow-wrap: anywhere;
	}

	.pct {
		color: var(--label-2);
		text-align: end;
	}

	.empty {
		margin: 0;
		font-size: 0.875rem;
		color: var(--label-2);
	}

	/* Token-coloured fills for the stacked bar and legend swatches; the legend names every source. */
	.fill-accent {
		background: var(--accent);
	}

	.fill-ok {
		background: var(--ok);
	}

	.fill-warn {
		background: var(--warn);
	}

	.fill-danger {
		background: var(--danger-fill);
	}

	.fill-neutral {
		background: var(--label-3);
	}

	.num {
		font-variant-numeric: tabular-nums;
		font-weight: 600;
	}

	.note,
	.version {
		margin: 0;
		padding: 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	.version {
		font-size: 0.75rem;
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

	@container dash (min-width: 56.25rem) {
		.grid {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}

	/* Phones keep the three headline numbers in one row; only the tile chrome gets smaller. */
	@media (max-width: 32.49rem) {
		.tiles {
			gap: 0.5rem;
		}

		.tiles :global(.tile) {
			gap: 0.25rem;
			padding: 0.625rem 0.75rem;
		}

		.tiles :global(.value) {
			font-size: 1.5rem;
		}
	}
</style>
