<script lang="ts">
	import Button from './Button.svelte';
	import { errorMessage } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		/** Stable control-api or client code. The message is looked up from it; unknown codes get the fallback. */
		code: string;
		/** Non-secret params from the envelope. Rendered as text only. */
		params?: Record<string, unknown>;
		onretry?: () => void;
	}

	let { code, params = {}, onretry }: Props = $props();
	let copied = $state(false);
	const message = $derived(errorMessage(code, params));

	async function copyCode(): Promise<void> {
		try {
			await globalThis.navigator.clipboard.writeText(code);
			copied = true;
		} catch {
			copied = false;
		}
	}
</script>

<div class="error" role="alert">
	<p class="message">{message}</p>
	<p class="code">
		<span>{m.error_code_label()}</span>
		<code>{code}</code>
	</p>
	<div class="actions">
		<Button onclick={copyCode}>{copied ? m.action_copied() : m.action_copy()}</Button>
		{#if onretry}
			<Button variant="primary" onclick={onretry}>{m.action_retry()}</Button>
		{/if}
	</div>
</div>

<style>
	.error {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-4);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		color: var(--label);
	}

	.message {
		margin: 0;
		font-weight: 600;
		overflow-wrap: anywhere;
	}

	.code {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	code {
		font-family: var(--font-mono);
		overflow-wrap: anywhere;
		user-select: all;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}
</style>
