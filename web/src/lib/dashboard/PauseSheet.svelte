<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import { failureOf } from '$lib/api/result';
	import { FILTER_SET, pauseFilterSet, type PauseDuration } from '$lib/api/stats';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		/** Mounted only while a pause is being confirmed, so the sheet always opens fresh. */
		duration: PauseDuration;
		onclose: () => void;
		/** Receives the RFC 3339 instant the pause ends. */
		onpaused: (until: string) => void;
	}

	let { duration, onclose, onpaused }: Props = $props();

	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	const durationText = $derived(
		duration === 'PT1H' ? m.dashboard_duration_1h() : m.dashboard_duration_5m(),
	);

	async function confirm(): Promise<void> {
		busy = true;
		failure = null;
		try {
			const result = await pauseFilterSet(duration);
			onpaused(result.paused_until);
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

<Sheet open={true} title={m.dashboard_pause_title({ duration: durationText })} {onclose}>
	<p class="body">{m.dashboard_pause_body({ set: FILTER_SET, duration: durationText })}</p>
	{#if failure}
		<div class="notice">
			<ErrorNotice code={failure.code} params={failure.params} />
		</div>
	{/if}
	<div class="actions">
		<Button onclick={onclose}>{m.action_cancel()}</Button>
		<Button variant="primary" disabled={busy} onclick={confirm}
			>{m.dashboard_pause_confirm()}</Button
		>
	</div>
</Sheet>

<style>
	.body {
		margin: 0;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.notice {
		margin-top: 0.75rem;
	}

	.actions {
		display: flex;
		justify-content: flex-end;
		flex-wrap: wrap;
		gap: 0.625rem;
		margin-top: 1.125rem;
	}
</style>
