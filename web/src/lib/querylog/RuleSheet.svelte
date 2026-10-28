<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { ApiError } from '$lib/api/client';
	import { listFilterSets, type FilterSet } from '$lib/api/filtering';
	import { allowTemporarily } from '$lib/api/query-log';
	import { failureOf } from '$lib/api/result';
	import { m } from '$lib/paraglide/messages';
	import Value from './Value.svelte';
	import {
		isTemporary,
		preferredSetId,
		writePermanentRule,
		type RuleAction,
		type RuleOutcome,
		type RuleValidity,
	} from './rule-write';

	interface Props {
		/** The ASCII owner name the API stores; shown as text. */
		domain: string;
		/** The filter set that decided the query, when the record names one. */
		filterSet?: string;
		/** Opposite of the query's verdict; the caller derives it from the record status. */
		defaultAction: RuleAction;
		onclose: () => void;
		onsaved: (outcome: RuleOutcome) => void;
	}

	let { domain, filterSet, defaultAction, onclose, onsaved }: Props = $props();

	type Failure = { code: string; params: Record<string, unknown> };

	const uid = $props.id();
	// The initial values are a snapshot on purpose: the sheet is opened fresh for each decision.
	// svelte-ignore state_referenced_locally
	let action = $state<RuleAction>(defaultAction);
	let includeSubdomains = $state(false);
	let validity = $state<RuleValidity>('PT5M');
	let sets = $state<FilterSet[]>([]);
	let setsLoaded = $state(false);
	let setsFailure = $state<Failure | null>(null);
	let setId = $state('');
	let busy = $state(false);
	let unavailable = $state(false);
	let failure = $state<Failure | null>(null);

	const temporary = $derived(isTemporary(action, validity));
	const needsSet = $derived(!temporary);
	const noSets = $derived(setsLoaded && sets.length === 0);
	const disabled = $derived(busy || unavailable || (needsSet && (!setsLoaded || noSets)));

	const actionOptions = $derived<{ value: RuleAction; label: string }[]>([
		{ value: 'allow', label: m.querylog_rule_action_allow() },
		{ value: 'block', label: m.querylog_rule_action_block() },
	]);
	const validityOptions = $derived<{ value: RuleValidity; label: string }[]>([
		{ value: 'PT5M', label: m.dashboard_pause_5m() },
		{ value: 'PT15M', label: m.querylog_duration_15m() },
		{ value: 'PT1H', label: m.dashboard_pause_1h() },
		{ value: 'permanent', label: m.querylog_rule_permanent() },
	]);
	const confirmLabel = $derived(
		temporary
			? m.querylog_allow_confirm()
			: action === 'allow'
				? m.querylog_rule_confirm_allow_permanent()
				: m.querylog_rule_confirm_block(),
	);

	async function loadSets(): Promise<void> {
		try {
			sets = await listFilterSets();
			setId = preferredSetId(sets, filterSet);
		} catch (cause) {
			setsFailure = failureOf(cause);
		} finally {
			setsLoaded = true;
		}
	}

	async function confirm(): Promise<void> {
		busy = true;
		unavailable = false;
		failure = null;
		try {
			const duration = validity;
			if (isTemporary(action, duration)) {
				const result = await allowTemporarily({
					domain,
					include_subdomains: includeSubdomains,
					duration,
					...(setId ? { filter_set_id: setId } : {}),
				});
				onsaved({ kind: 'temporary', result });
			} else {
				const result = await writePermanentRule(
					{ action, domain, include_subdomains: includeSubdomains },
					setId,
				);
				if (result.status === 'unknown_set') {
					failure = { code: 'control_api.not_found', params: {} };
					return;
				}
				onsaved({ kind: 'permanent', result });
			}
		} catch (cause) {
			// 404 on the temporary path: the node does not run temporary allows (an MCP-phase endpoint).
			if (temporary && cause instanceof ApiError && cause.status === 404) unavailable = true;
			else failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void loadSets();
	});
</script>

<Sheet open={true} title={m.querylog_rule_title({ domain })} {onclose}>
	<div class="row">
		<span id={`${uid}-domain`}>{m.querylog_allow_domain()}</span>
		<span class="domain-value" aria-labelledby={`${uid}-domain`}><Value value={domain} mono /></span
		>
	</div>
	<div class="stack">
		<span class="label">{m.querylog_rule_action()}</span>
		<Segmented options={actionOptions} bind:value={action} label={m.querylog_rule_action()} />
	</div>
	<div class="row">
		<div class="switch-text">
			<span id={`${uid}-sub`}>{m.querylog_allow_subdomains()}</span>
			<span class="meta">{m.querylog_allow_subdomains_meta()}</span>
		</div>
		<Switch bind:checked={includeSubdomains} aria-labelledby={`${uid}-sub`} />
	</div>
	{#if action === 'allow'}
		<div class="stack">
			<span class="label">{m.querylog_rule_validity()}</span>
			<Segmented
				options={validityOptions}
				bind:value={validity}
				label={m.querylog_rule_validity()}
			/>
		</div>
	{/if}
	{#if !temporary}
		<p class="meta">{m.querylog_rule_permanent_hint()}</p>
	{/if}
	{#if setsFailure}
		<div class="notice">
			<ErrorNotice code={setsFailure.code} params={setsFailure.params} />
		</div>
	{:else if sets.length > 1}
		<div class="stack">
			<label class="label" for={`${uid}-set`}>{m.querylog_row_filter_set()}</label>
			<select id={`${uid}-set`} class="select mono" bind:value={setId}>
				{#each sets as set (set.id)}
					<option value={set.id}>{set.name || set.id}</option>
				{/each}
			</select>
		</div>
	{/if}
	{#if needsSet && noSets && !setsFailure}
		<p class="notice">{m.querylog_rule_no_sets()}</p>
	{/if}
	{#if unavailable}
		<p class="notice">{m.querylog_allow_unavailable()}</p>
	{:else if failure}
		<div class="notice">
			<ErrorNotice code={failure.code} params={failure.params} />
		</div>
	{/if}
	<div class="actions">
		<Button onclick={onclose}>{m.action_cancel()}</Button>
		<Button variant="primary" {disabled} onclick={confirm}>{confirmLabel}</Button>
	</div>
</Sheet>

<style>
	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		min-height: 2.75rem;
		margin-top: 0.875rem;
	}

	.domain-value {
		min-width: 0;
		text-align: end;
	}

	.switch-text {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}

	.meta {
		margin: 0.5rem 0 0;
		font-size: 0.8125rem;
		color: var(--label-2);
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

	.select {
		box-sizing: border-box;
		width: 100%;
		min-height: var(--control-h);
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font: inherit;
	}

	.mono {
		font-family: var(--font-mono);
	}

	.notice {
		margin: 0.75rem 0 0;
		color: var(--warn);
	}

	.actions {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: 0.625rem;
		margin-top: 1.125rem;
	}
</style>
