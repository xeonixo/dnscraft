<script lang="ts">
	import Button from './Button.svelte';
	import ErrorNotice from './ErrorNotice.svelte';
	import Sheet from './Sheet.svelte';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		title: string;
		/** Plain text naming the object (and, if needed, the consequence). */
		body: string;
		confirmLabel?: string;
		busy?: boolean;
		failure?: { code: string; params: Record<string, unknown> } | null;
		onconfirm: () => void;
		oncancel: () => void;
	}

	let {
		title,
		body,
		confirmLabel,
		busy = false,
		failure = null,
		onconfirm,
		oncancel,
	}: Props = $props();
</script>

<Sheet open={true} {title} onclose={oncancel} centeredOnWide>
	<p class="body">{body}</p>
	{#if failure}<ErrorNotice code={failure.code} params={failure.params} />{/if}
	<div class="actions">
		<Button variant="secondary" onclick={oncancel}>{m.action_cancel()}</Button>
		<Button variant="danger" disabled={busy} onclick={onconfirm}>
			{confirmLabel ?? m.action_delete()}
		</Button>
	</div>
</Sheet>

<style>
	.body {
		margin: 0 0 var(--space-4);
		overflow-wrap: anywhere;
	}
	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: var(--space-2);
		margin-top: var(--space-3);
	}
</style>
