<script lang="ts">
	import { onMount } from 'svelte';
	import { SvelteMap } from 'svelte/reactivity';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import { ApiError } from '$lib/api/client';
	import { listFilterSets, type FilterSet } from '$lib/api/filtering';
	import {
		confirmMcpProposal,
		listAllMcpRules,
		listMcpProposals,
		rejectMcpProposal,
		removeMcpRule,
		resumeFilterSet,
		type McpProposal,
		type McpRuleKind,
		type McpRuleRow,
	} from '$lib/api/mcp-rules';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { formatRelativeTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';
	import { ruleDomainProblem, type RuleAction } from '$lib/policy/rule-lines';
	import {
		preferredSetId,
		removePermanentRule,
		writePermanentRule,
	} from '$lib/querylog/rule-write';
	import StatusMark from '$lib/querylog/StatusMark.svelte';
	import {
		buildRuleEntries,
		filterEntries,
		isLive,
		minutesLeft,
		type ActionFilter,
		type RuleEntry,
	} from '$lib/rules/entries';
	import { displayText } from '$lib/safe-text';

	type Failure = { code: string; params: Record<string, unknown> };
	/** A temporary allow or a pause that is running now. */
	interface ActiveRow {
		key: string;
		setId: string;
		setName: string;
		domain: string;
		includeSubdomains: boolean | null;
		instant: string;
	}
	interface Model {
		sets: FilterSet[];
		entries: RuleEntry[];
		allows: ActiveRow[];
		pauses: ActiveRow[];
		/** Exceptions an assistant proposed; they wait for the owner. */
		proposals: McpProposal[];
		/** The node does not serve MCP-managed rules (the reads answered 404). */
		mcpUnavailable: boolean;
	}

	const isAdmin = $derived(auth.role === 'admin');
	const locale = getLocale();

	let result = $state<Result<Model>>({ kind: 'loading' });
	const model = $derived(result.kind === 'ok' ? result.data : null);

	let query = $state('');
	let actionFilter = $state<ActionFilter>('all');
	let setFilter = $state('all');
	const visible = $derived(
		model ? filterEntries(model.entries, { query, action: actionFilter, setId: setFilter }) : [],
	);

	/** Success line above the list (saved, removed, resumed). */
	let notice = $state<string | null>(null);
	let pageFailure = $state<Failure | null>(null);
	let busy = $state(false);

	let detail = $state<RuleEntry | null>(null);
	let confirmRemove = $state(false);
	let detailFailure = $state<Failure | null>(null);
	let detailNote = $state<string | null>(null);

	let addOpen = $state(false);
	let addAction = $state<RuleAction>('block');
	let addDomain = $state('');
	let addSubdomains = $state(false);
	let addSetId = $state('');
	let addProblem = $state<string | null>(null);
	let addNote = $state<string | null>(null);
	let addFailure = $state<Failure | null>(null);

	const filterOptions = $derived<{ value: ActionFilter; label: string }[]>([
		{ value: 'all', label: m.rules_filter_all() },
		{ value: 'block', label: m.rules_filter_blocked() },
		{ value: 'allow', label: m.rules_filter_allowed() },
	]);
	const addActionOptions = $derived<{ value: RuleAction; label: string }[]>([
		{ value: 'block', label: m.rules_action_block() },
		{ value: 'allow', label: m.rules_action_allow() },
	]);

	/** Null when the node does not serve the MCP kind for this set (404): treated as no rows. */
	async function readMcp(kind: McpRuleKind, setId: string): Promise<McpRuleRow[] | null> {
		try {
			return await listAllMcpRules(kind, setId);
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 404) return null;
			throw cause;
		}
	}

	/** A node without the proposals endpoint (404) simply has none. */
	async function readProposals(): Promise<McpProposal[]> {
		try {
			return await listMcpProposals();
		} catch (cause) {
			if (cause instanceof ApiError && cause.status === 404) return [];
			throw cause;
		}
	}

	async function loadModel(): Promise<Model> {
		const [sets, proposals] = await Promise.all([listFilterSets(), readProposals()]);
		const now = new Date();
		const perSet = await Promise.all(
			sets.map(async (set) => {
				const [rules, allows, pauses] = await Promise.all([
					readMcp('rules', set.id),
					readMcp('temporary_allows', set.id),
					readMcp('pauses', set.id),
				]);
				return { set, rules, allows, pauses };
			}),
		);

		const mcpBySet = new SvelteMap<string, McpRuleRow[]>();
		const allows: ActiveRow[] = [];
		const pauses: ActiveRow[] = [];
		let mcpUnavailable = false;
		for (const { set, rules, allows: running, pauses: paused } of perSet) {
			if (rules === null || running === null || paused === null) mcpUnavailable = true;
			mcpBySet.set(set.id, rules ?? []);
			const setName = set.name || set.id;
			for (const [position, row] of (running ?? []).entries()) {
				if (!isLive(row.expires_at ?? '', now)) continue;
				allows.push({
					key: `allow:${set.id}:${position}`,
					setId: set.id,
					setName,
					domain: row.domain,
					includeSubdomains: row.include_subdomains ?? null,
					instant: row.expires_at ?? '',
				});
			}
			for (const row of paused ?? []) {
				const instant = row.paused_until ?? '';
				if (!isLive(instant, now)) continue;
				pauses.push({
					key: `pause:${set.id}`,
					setId: set.id,
					setName,
					domain: '',
					includeSubdomains: null,
					instant,
				});
			}
		}

		return {
			sets,
			entries: buildRuleEntries(sets, mcpBySet),
			allows,
			pauses,
			proposals,
			mcpUnavailable,
		};
	}

	async function load(): Promise<void> {
		result = await settle(loadModel());
	}

	function scopeOf(includeSubdomains: boolean | null): string {
		if (includeSubdomains === true) return m.rules_scope_subdomains();
		if (includeSubdomains === false) return m.rules_scope_exact();
		return '';
	}

	/** "läuft ab in 29 Tagen", "unbefristet", or "abgelaufen" for an MCP rule. */
	function expiryOf(entry: RuleEntry): string {
		if (!entry.expiresAt) return m.rules_expiry_none();
		const instant = Date.parse(entry.expiresAt);
		if (Number.isNaN(instant)) return m.rules_expiry_none();
		const now = new Date();
		if (instant <= now.getTime()) return m.rules_expired();
		return m.rules_expires_in({ when: formatRelativeTime(new Date(instant), now, locale) });
	}

	function sublineOf(entry: RuleEntry): string {
		const parts = [
			m.rules_set_line({ set: displayText(entry.setName, 60).text }),
			entry.source === 'mcp' ? m.rules_origin_mcp() : m.rules_origin_text(),
			entry.source === 'mcp' ? expiryOf(entry) : '',
			scopeOf(entry.includeSubdomains),
		];
		return parts.filter((part) => part !== '').join(' · ');
	}

	function activeDetailOf(row: ActiveRow): string {
		return [
			m.rules_origin_temp(),
			m.rules_set_line({ set: displayText(row.setName, 60).text }),
			m.rules_remaining({ minutes: minutesLeft(row.instant, new Date()) }),
			scopeOf(row.includeSubdomains),
		]
			.filter((part) => part !== '')
			.join(' · ');
	}

	function proposalDetailOf(proposal: McpProposal): string {
		const setName = model?.sets.find((set) => set.id === proposal.filter_set_id)?.name;
		const expires = proposal.expires_at ? Date.parse(proposal.expires_at) : Number.NaN;
		return [
			m.rules_set_line({ set: displayText(setName || proposal.filter_set_id, 60).text }),
			scopeOf(proposal.include_subdomains),
			proposal.reason
				? m.rules_proposal_reason({ reason: displayText(proposal.reason, 200).text })
				: '',
			Number.isNaN(expires)
				? ''
				: m.rules_expires_in({ when: formatRelativeTime(new Date(expires), new Date(), locale) }),
		]
			.filter((part) => part !== '')
			.join(' · ');
	}

	async function decide(proposal: McpProposal, confirm: boolean): Promise<void> {
		busy = true;
		pageFailure = null;
		notice = null;
		try {
			if (confirm) {
				const done = await confirmMcpProposal(proposal.id);
				const setName = model?.sets.find((set) => set.id === done.filter_set_id)?.name;
				notice = m.rules_proposal_done({
					rule: displayText(done.rule_text, 120).text,
					set: displayText(setName || done.filter_set_id, 60).text,
				});
			} else {
				await rejectMcpProposal(proposal.id);
				notice = m.rules_proposal_rejected();
			}
			await load();
		} catch (cause) {
			pageFailure = failureOf(cause);
			// The proposal may be gone (expired or decided elsewhere): show the real list.
			await load();
		} finally {
			busy = false;
		}
	}

	function pausedDetailOf(row: ActiveRow): string {
		return [
			m.rules_paused(),
			m.rules_remaining({ minutes: minutesLeft(row.instant, new Date()) }),
		].join(' · ');
	}

	// A success line fades after a few seconds; any new action replaces it sooner.
	$effect(() => {
		if (notice === null) return;
		const timer = setTimeout(() => (notice = null), 6000);
		return () => clearTimeout(timer);
	});

	function openAdd(): void {
		addAction = 'block';
		addDomain = '';
		addSubdomains = false;
		addProblem = null;
		addNote = null;
		addFailure = null;
		addSetId = preferredSetId(model?.sets ?? []);
		addOpen = true;
	}

	async function submitAdd(): Promise<void> {
		addNote = null;
		addFailure = null;
		const problem = ruleDomainProblem(addDomain);
		addProblem =
			problem === 'empty'
				? m.rules_add_domain_empty()
				: problem === 'invalid'
					? m.rules_add_domain_invalid()
					: null;
		if (problem) return;

		busy = true;
		try {
			const outcome = await writePermanentRule(
				{ action: addAction, domain: addDomain.trim(), include_subdomains: addSubdomains },
				addSetId,
			);
			if (outcome.status === 'unknown_set') {
				addFailure = { code: 'control_api.not_found', params: {} };
				return;
			}
			const setName = displayText(outcome.filterSetName, 60).text;
			if (outcome.status === 'exists') {
				addNote = m.rules_add_exists({ set: setName });
				return;
			}
			addOpen = false;
			notice = m.rules_add_done({ rule: displayText(outcome.ruleText, 120).text, set: setName });
			await load();
		} catch (cause) {
			addFailure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	function openDetails(entry: RuleEntry): void {
		detail = entry;
		confirmRemove = false;
		detailFailure = null;
		detailNote = null;
	}

	function closeDetails(): void {
		detail = null;
		confirmRemove = false;
	}

	async function removeEntry(entry: RuleEntry): Promise<void> {
		busy = true;
		detailFailure = null;
		detailNote = null;
		try {
			if (entry.source === 'mcp') {
				await removeMcpRule(entry.domain, entry.setId);
			} else {
				const outcome = await removePermanentRule(entry.setId, entry.lineIndex, entry.ruleText);
				if (outcome !== 'removed') {
					confirmRemove = false;
					detailNote = m.rules_remove_missing();
					await load();
					return;
				}
			}
			closeDetails();
			notice = m.rules_removed();
			await load();
		} catch (cause) {
			detailFailure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function resume(row: ActiveRow): Promise<void> {
		busy = true;
		pageFailure = null;
		notice = null;
		try {
			await resumeFilterSet(row.setId);
			notice = m.rules_resumed({ set: displayText(row.setName, 60).text });
			await load();
		} catch (cause) {
			pageFailure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

{#snippet ruleBody(entry: RuleEntry)}
	<span class="rule-main">
		{#if entry.advanced}
			<span class="rule-domain">{m.rules_advanced()}</span>
			<span class="rule-raw mono">{displayText(entry.ruleText, 200).text}</span>
		{:else}
			<span class="rule-domain mono">{displayText(entry.domain).text}</span>
		{/if}
		<span class="rule-detail">{sublineOf(entry)}</span>
	</span>
	{#if entry.action === 'allow'}
		<StatusMark icon="check-circle" tone="ok" label={m.rules_mark_allowed()} />
	{:else}
		<StatusMark icon="ban" tone="danger" label={m.rules_mark_blocked()} />
	{/if}
{/snippet}

<div class="rules">
	<div class="page-head">
		<p class="lead">{m.rules_intro()}</p>
		{#if isAdmin}
			<Button variant="primary" onclick={openAdd}>{m.rules_add()}</Button>
		{/if}
	</div>

	{#if notice}
		<p class="notice" role="status">{notice}</p>
	{/if}
	{#if pageFailure}
		<div class="notice">
			<ErrorNotice code={pageFailure.code} params={pageFailure.params} />
		</div>
	{/if}

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void load()} />
	{:else if model}
		{#if model.mcpUnavailable}
			<p class="meta">{m.rules_mcp_unavailable()}</p>
		{/if}

		{#if model.proposals.length > 0}
			<section class="block" aria-labelledby="rules-proposals-head">
				<h2 id="rules-proposals-head" class="section-head">{m.rules_proposals_heading()}</h2>
				<p class="meta">{m.rules_proposals_intro()}</p>
				<ul class="rule-list">
					{#each model.proposals as proposal (proposal.id)}
						<li class="rule-row static proposal">
							<span class="rule-main">
								<span class="rule-domain mono">{displayText(proposal.domain).text}</span>
								<span class="rule-detail">{proposalDetailOf(proposal)}</span>
							</span>
							{#if isAdmin}
								<span class="proposal-actions">
									<button
										type="button"
										class="text-action"
										disabled={busy}
										onclick={() => void decide(proposal, true)}
									>
										{m.rules_proposal_allow()}
									</button>
									<button
										type="button"
										class="danger-text"
										disabled={busy}
										onclick={() => void decide(proposal, false)}
									>
										{m.rules_proposal_reject()}
									</button>
								</span>
							{/if}
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		{#if model.allows.length > 0 || model.pauses.length > 0}
			<section class="block" aria-labelledby="rules-active-head">
				<h2 id="rules-active-head" class="section-head">{m.rules_active_heading()}</h2>
				<ul class="rule-list">
					{#each model.allows as allow (allow.key)}
						<li class="rule-row static">
							<span class="rule-main">
								<span class="rule-domain mono">{displayText(allow.domain).text}</span>
								<span class="rule-detail">{activeDetailOf(allow)}</span>
							</span>
							<StatusMark icon="check-circle" tone="ok" label={m.rules_mark_allowed()} />
						</li>
					{/each}
					{#each model.pauses as pause (pause.key)}
						<li class="rule-row static">
							<span class="rule-main">
								<span class="rule-domain">{displayText(pause.setName, 60).text}</span>
								<span class="rule-detail">{pausedDetailOf(pause)}</span>
							</span>
							{#if isAdmin}
								<button
									type="button"
									class="text-action"
									disabled={busy}
									onclick={() => void resume(pause)}
								>
									{m.rules_resume()}
								</button>
							{/if}
						</li>
					{/each}
				</ul>
			</section>
		{/if}

		<section class="block" aria-labelledby="rules-all-head">
			<h2 id="rules-all-head" class="section-head">{m.rules_list_heading()}</h2>
			{#if model.entries.length === 0}
				<div class="empty">
					<p>{m.rules_empty_body()}</p>
					{#if isAdmin}
						<Button variant="primary" onclick={openAdd}>{m.rules_add()}</Button>
					{/if}
				</div>
			{:else}
				<div class="filters">
					<input
						type="search"
						class="field search"
						aria-label={m.rules_search_label()}
						placeholder={m.rules_search_label()}
						bind:value={query}
					/>
					<Segmented
						options={filterOptions}
						bind:value={actionFilter}
						label={m.rules_action_label()}
					/>
					{#if model.sets.length > 1}
						<select class="field" aria-label={m.rules_filter_set_label()} bind:value={setFilter}>
							<option value="all">{m.rules_filter_set_all()}</option>
							{#each model.sets as set (set.id)}
								<option value={set.id}>{displayText(set.name || set.id, 60).text}</option>
							{/each}
						</select>
					{/if}
				</div>

				{#if visible.length === 0}
					<p class="state">{m.rules_none_match()}</p>
				{:else}
					<ul class="rule-list">
						{#each visible as entry (entry.key)}
							<li>
								{#if isAdmin}
									<button type="button" class="rule-row" onclick={() => openDetails(entry)}>
										{@render ruleBody(entry)}
									</button>
								{:else}
									<div class="rule-row">
										{@render ruleBody(entry)}
									</div>
								{/if}
							</li>
						{/each}
					</ul>
				{/if}
			{/if}
		</section>
	{/if}
</div>

{#if detail}
	{@const entry = detail}
	<Sheet open={true} title={m.rules_details_title()} onclose={closeDetails} centeredOnWide>
		<dl class="facts">
			<div>
				<dt>{m.rules_field_text()}</dt>
				<dd class="mono">{displayText(entry.ruleText, 200).text}</dd>
			</div>
			<div>
				<dt>{m.rules_field_set()}</dt>
				<dd>{displayText(entry.setName, 60).text}</dd>
			</div>
			<div>
				<dt>{m.rules_field_origin()}</dt>
				<dd>{entry.source === 'mcp' ? m.rules_origin_mcp() : m.rules_origin_text()}</dd>
			</div>
			{#if scopeOf(entry.includeSubdomains)}
				<div>
					<dt>{m.rules_field_scope()}</dt>
					<dd>{scopeOf(entry.includeSubdomains)}</dd>
				</div>
			{/if}
			{#if entry.source === 'mcp'}
				<div>
					<dt>{m.rules_field_validity()}</dt>
					<dd>{expiryOf(entry)}</dd>
				</div>
			{/if}
		</dl>

		{#snippet footer()}
			{#if detailFailure}
				<div class="footer-error">
					<ErrorNotice code={detailFailure.code} params={detailFailure.params} />
				</div>
			{/if}
			{#if detailNote}
				<p class="footer-note">{detailNote}</p>
			{/if}
			{#if confirmRemove}
				<p class="confirm-text">{m.rules_remove_question()}</p>
				<div class="actions">
					<Button variant="secondary" onclick={() => (confirmRemove = false)}>
						{m.action_cancel()}
					</Button>
					<Button variant="danger" disabled={busy} onclick={() => void removeEntry(entry)}>
						{m.rules_remove()}
					</Button>
				</div>
			{:else}
				<button type="button" class="danger-text" onclick={() => (confirmRemove = true)}>
					{m.rules_remove()}
				</button>
				<div class="actions">
					<Button variant="secondary" onclick={closeDetails}>{m.action_close()}</Button>
				</div>
			{/if}
		{/snippet}
	</Sheet>
{/if}

{#if addOpen && isAdmin}
	<Sheet open={true} title={m.rules_add()} onclose={() => (addOpen = false)} centeredOnWide>
		<div class="stack">
			<span class="label">{m.rules_action_label()}</span>
			<Segmented options={addActionOptions} bind:value={addAction} label={m.rules_action_label()} />
		</div>
		<div class="stack">
			<label class="label" for="rule-add-domain">{m.rules_add_domain()}</label>
			<input
				id="rule-add-domain"
				class="field mono"
				autocomplete="off"
				spellcheck="false"
				aria-invalid={addProblem ? 'true' : undefined}
				bind:value={addDomain}
				oninput={() => ((addProblem = null), (addNote = null), (addFailure = null))}
			/>
		</div>
		<div class="row">
			<span id="rule-add-subs">{m.rules_add_subdomains()}</span>
			<Switch bind:checked={addSubdomains} aria-labelledby="rule-add-subs" />
		</div>
		<p class="meta">{m.rules_add_subdomains_meta()}</p>

		{#if model && model.sets.length > 1}
			<div class="stack">
				<label class="label" for="rule-add-set">{m.rules_field_set()}</label>
				<select id="rule-add-set" class="field" bind:value={addSetId}>
					{#each model.sets as set (set.id)}
						<option value={set.id}>{displayText(set.name || set.id, 60).text}</option>
					{/each}
				</select>
			</div>
		{/if}
		{#if model && model.sets.length === 0}
			<p class="notice">{m.rules_no_sets()}</p>
		{/if}

		{#if addProblem}
			<p class="notice">{addProblem}</p>
		{/if}
		{#if addNote}
			<p class="notice">{addNote}</p>
		{/if}
		{#if addFailure}
			<div class="notice">
				<ErrorNotice code={addFailure.code} params={addFailure.params} />
			</div>
		{/if}

		{#snippet footer()}
			<div class="actions">
				<Button variant="secondary" onclick={() => (addOpen = false)}>{m.action_cancel()}</Button>
				<Button
					variant="primary"
					disabled={busy || !model || model.sets.length === 0}
					onclick={() => void submitAdd()}
				>
					{m.rules_add()}
				</Button>
			</div>
		{/snippet}
	</Sheet>
{/if}

<style>
	.rules {
		max-width: 60rem;
	}

	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
		margin-bottom: var(--space-4);
	}
	.lead {
		max-width: 40rem;
		margin: 0;
		color: var(--label-2);
	}
	.state,
	.meta {
		margin: 0.75rem 0 0;
		color: var(--label-2);
		font-size: 0.875rem;
	}
	.notice {
		margin: 0.75rem 0;
	}

	.block {
		margin-top: var(--space-5);
	}
	.section-head {
		margin: 0 0 var(--space-2);
		font-size: 0.9375rem;
		font-weight: 600;
	}
	.empty {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-3);
		padding: var(--space-5);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
	}
	.empty p {
		margin: 0;
		color: var(--label-2);
	}

	.filters {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-3);
	}
	.search {
		flex: 1 1 14rem;
		min-width: 0;
	}

	.rule-list {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		margin: 0;
		padding: 0;
		list-style: none;
	}
	.rule-row {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		box-sizing: border-box;
		width: 100%;
		min-width: 0;
		padding: var(--space-3) var(--space-4);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		background: var(--surface);
		color: var(--label);
		font: inherit;
		text-align: start;
	}
	button.rule-row {
		cursor: pointer;
	}
	button.rule-row:hover {
		background: var(--surface-2);
	}
	.rule-main {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}
	.rule-domain {
		font-size: 1rem;
		font-weight: 600;
		overflow-wrap: anywhere;
	}
	.rule-raw {
		font-size: 0.8125rem;
		overflow-wrap: anywhere;
	}
	.rule-detail {
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.mono {
		font-family: var(--font-mono);
	}

	.field {
		box-sizing: border-box;
		min-height: var(--control-h);
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font: inherit;
	}
	.text-action,
	.danger-text {
		align-self: flex-start;
		min-height: var(--control-h);
		padding: 0 0.25rem;
		border: none;
		background: transparent;
		font: inherit;
		font-weight: 500;
		cursor: pointer;
	}
	.text-action {
		color: var(--accent);
	}
	.proposal {
		flex-wrap: wrap;
	}
	.proposal .rule-main {
		flex-basis: 14rem;
	}
	.proposal-actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}
	.danger-text {
		color: var(--danger);
	}

	.facts {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		margin: 0;
	}
	.facts div {
		display: flex;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}
	.facts dt {
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.facts dd {
		margin: 0;
		overflow-wrap: anywhere;
	}

	.stack {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		margin-top: 0.875rem;
	}
	.label {
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		min-height: 2.75rem;
		margin-top: 0.875rem;
	}

	.footer-error {
		flex: 0 0 100%;
	}
	.footer-note,
	.confirm-text {
		flex: 0 0 100%;
		margin: 0;
		color: var(--label);
	}
	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: var(--space-2);
		margin-inline-start: auto;
	}
</style>
