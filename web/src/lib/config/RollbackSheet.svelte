<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		/** The version the configuration is restored from. */
		version: number;
		busy: boolean;
		failure: { code: string; params: Record<string, unknown> } | null;
		onconfirm: () => void;
		onclose: () => void;
	}

	let { version, busy, failure, onconfirm, onclose }: Props = $props();
</script>

<!-- Cancel comes first, so opening the sheet focuses the safe choice, not the rollback. -->
<Sheet open={true} title={m.config_rollback_title({ version })} {onclose}>
	<p class="body">{m.config_rollback_body({ version })}</p>
	{#if failure}
		<div class="notice">
			<ErrorNotice code={failure.code} params={failure.params} />
		</div>
	{/if}
	<div class="actions">
		<Button onclick={onclose}>{m.action_cancel()}</Button>
		<Button variant="danger" disabled={busy} onclick={onconfirm}>
			{m.config_rollback_confirm()}
		</Button>
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
