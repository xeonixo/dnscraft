<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import { failureOf } from '$lib/api/result';
	import { flushCache, type FlushResult } from '$lib/api/stats';
	import { toDomainName } from '$lib/domain-name';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		/** Mounted only while the sheet is open, so every opening starts with an empty form. */
		onclose: () => void;
		onflushed: (result: FlushResult) => void;
	}

	type Scope = 'all' | 'domain';

	let { onclose, onflushed }: Props = $props();

	const uid = $props.id();
	const domainId = `${uid}-domain`;
	const errorId = `${uid}-domain-error`;

	let scope = $state<Scope>('all');
	let domain = $state('');
	let domainInvalid = $state(false);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	const scopeOptions = $derived<{ value: Scope; label: string }[]>([
		{ value: 'all', label: m.dashboard_cache_scope_all() },
		{ value: 'domain', label: m.dashboard_cache_scope_domain() },
	]);

	async function submit(): Promise<void> {
		failure = null;
		domainInvalid = false;
		let target: string | null = null;
		if (scope === 'domain') {
			target = toDomainName(domain);
			if (target === null) {
				domainInvalid = true;
				return;
			}
		}
		busy = true;
		try {
			onflushed(await flushCache(target));
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

<Sheet open={true} title={m.dashboard_cache_title()} {onclose}>
	<p class="body">{m.dashboard_cache_body()}</p>
	<div class="scope">
		<Segmented options={scopeOptions} bind:value={scope} label={m.dashboard_cache_scope_label()} />
	</div>
	{#if scope === 'domain'}
		<label class="field-label" for={domainId}>{m.dashboard_cache_domain_label()}</label>
		<input
			id={domainId}
			class="field"
			type="text"
			inputmode="url"
			autocomplete="off"
			autocapitalize="none"
			spellcheck="false"
			placeholder={m.dashboard_cache_domain_placeholder()}
			aria-invalid={domainInvalid}
			aria-describedby={domainInvalid ? errorId : undefined}
			bind:value={domain}
		/>
		{#if domainInvalid}
			<p class="field-error" id={errorId}>{m.dashboard_cache_domain_invalid()}</p>
		{/if}
	{/if}
	{#if failure}
		<div class="notice">
			<ErrorNotice code={failure.code} params={failure.params} />
		</div>
	{/if}
	<div class="actions">
		<Button onclick={onclose}>{m.action_cancel()}</Button>
		<Button variant="danger" disabled={busy} onclick={submit}>{m.dashboard_cache_confirm()}</Button>
	</div>
</Sheet>

<style>
	.body {
		margin: 0;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.scope {
		margin-top: 0.875rem;
	}

	.field-label {
		display: block;
		margin: 0.875rem 0 0.375rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	.field {
		box-sizing: border-box;
		width: 100%;
		min-height: 2.75rem;
		padding: 0.5rem 0.75rem;
		background: var(--surface-2);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		color: var(--label);
		font-family: var(--font-mono);
		font-size: 0.9375rem;
	}

	.field:focus-visible {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	.field[aria-invalid='true'] {
		border-color: var(--danger);
	}

	.field-error {
		margin: 0.375rem 0 0;
		font-size: 0.8125rem;
		color: var(--danger);
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
