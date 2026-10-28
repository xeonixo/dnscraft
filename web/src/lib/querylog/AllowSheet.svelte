<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { ApiError } from '$lib/api/client';
	import {
		allowTemporarily,
		type TempAllowDuration,
		type TempAllowResult,
	} from '$lib/api/query-log';
	import { failureOf } from '$lib/api/result';
	import { m } from '$lib/paraglide/messages';
	import Value from './Value.svelte';

	interface Props {
		/** The ASCII owner name the API stores; shown as text. */
		domain: string;
		/** The filter set that decided the query, when the record names one. */
		filterSet?: string;
		onclose: () => void;
		onallowed: (result: TempAllowResult) => void;
	}

	let { domain, filterSet, onclose, onallowed }: Props = $props();

	const uid = $props.id();
	let includeSubdomains = $state(false);
	let duration = $state<TempAllowDuration>('PT5M');
	let busy = $state(false);
	let unavailable = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	const durationOptions = $derived<{ value: TempAllowDuration; label: string }[]>([
		{ value: 'PT5M', label: m.dashboard_pause_5m() },
		{ value: 'PT15M', label: m.querylog_duration_15m() },
		{ value: 'PT1H', label: m.dashboard_pause_1h() },
	]);

	async function confirm(): Promise<void> {
		busy = true;
		unavailable = false;
		failure = null;
		try {
			onallowed(
				await allowTemporarily({
					domain,
					include_subdomains: includeSubdomains,
					duration,
					...(filterSet ? { filter_set_id: filterSet } : {}),
				}),
			);
		} catch (cause) {
			// 404: the node does not run temporary allows (an MCP-phase endpoint on older builds).
			if (cause instanceof ApiError && cause.status === 404) unavailable = true;
			else failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

<Sheet open={true} title={m.querylog_allow_title({ domain })} {onclose}>
	<p class="body">{m.querylog_allow_body()}</p>
	<div class="domain-row">
		<span id={`${uid}-domain`}>{m.querylog_allow_domain()}</span>
		<span class="domain-value" aria-labelledby={`${uid}-domain`}><Value value={domain} mono /></span
		>
	</div>
	<div class="switch-row">
		<div class="switch-text">
			<span id={`${uid}-sub`}>{m.querylog_allow_subdomains()}</span>
			<span class="meta">{m.querylog_allow_subdomains_meta()}</span>
		</div>
		<Switch bind:checked={includeSubdomains} aria-labelledby={`${uid}-sub`} />
	</div>
	<div class="duration">
		<span class="label">{m.querylog_allow_duration()}</span>
		<Segmented
			options={durationOptions}
			bind:value={duration}
			label={m.querylog_allow_duration()}
		/>
	</div>
	{#if unavailable}
		<p class="notice">{m.querylog_allow_unavailable()}</p>
	{:else if failure}
		<div class="notice">
			<ErrorNotice code={failure.code} params={failure.params} />
		</div>
	{/if}
	<div class="actions">
		<Button onclick={onclose}>{m.action_cancel()}</Button>
		<Button variant="primary" disabled={busy || unavailable} onclick={confirm}>
			{m.querylog_allow_confirm()}
		</Button>
	</div>
</Sheet>

<style>
	.body {
		margin: 0;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.domain-row,
	.switch-row {
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
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	.duration {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		margin-top: 0.875rem;
	}

	.label {
		font-size: 0.8125rem;
		color: var(--label-2);
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
