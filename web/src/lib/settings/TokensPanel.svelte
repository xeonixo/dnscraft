<script lang="ts">
	import { onMount } from 'svelte';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { getStatus } from '$lib/api/stats';
	import {
		createToken,
		listTokens,
		revokeToken,
		type ApiToken,
		type CreateTokenBody,
		type TokenScope,
	} from '$lib/api/tokens';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { displayText } from '$lib/safe-text';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		isAdmin: boolean;
	}

	let { isAdmin }: Props = $props();

	const locale = getLocale();
	const scopeOptions: { value: TokenScope; label: () => string }[] = [
		{ value: 'viewer', label: () => m.token_scope_viewer() },
		{ value: 'admin', label: () => m.token_scope_admin() },
		{ value: 'mcp:read', label: () => m.token_scope_mcp_read() },
		{ value: 'mcp:write', label: () => m.token_scope_mcp_write() },
	];

	let result = $state<Result<ApiToken[]>>({ kind: 'loading' });
	let sheetOpen = $state(false);
	let revokeTarget = $state<ApiToken | null>(null);
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);
	let plaintext = $state<string | null>(null);
	let selfSigned = $state(false);
	let confirmSelfSigned = $state(false);

	let formName = $state('');
	let formScope = $state<TokenScope>('viewer');

	async function load(): Promise<void> {
		if (!isAdmin) return;
		result = await settle(listTokens());
	}

	onMount(() => {
		void load();
		void getStatus()
			.then((status) => {
				selfSigned = status.tls_mode === 'self_signed';
			})
			.catch(() => {
				selfSigned = false;
			});
	});

	function scopeLabel(scope: string): string {
		const hit = scopeOptions.find((option) => option.value === scope);
		return hit ? hit.label() : scope;
	}

	function openCreate(): void {
		formName = '';
		formScope = 'viewer';
		confirmSelfSigned = false;
		failure = null;
		sheetOpen = true;
	}

	async function submitCreate(): Promise<void> {
		const mcpScope = formScope === 'mcp:read' || formScope === 'mcp:write';
		if (mcpScope && selfSigned && !confirmSelfSigned) {
			failure = { code: 'settings_token_self_signed_required', params: {} };
			return;
		}
		busy = true;
		failure = null;
		const body: CreateTokenBody = { name: formName.trim(), scope: formScope };
		try {
			const created = await createToken(body);
			plaintext = created.token;
			sheetOpen = false;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function copyPlaintext(): Promise<void> {
		if (!plaintext) return;
		try {
			await globalThis.navigator.clipboard.writeText(plaintext);
		} catch {
			/* clipboard may be denied */
		}
	}

	async function confirmRevoke(): Promise<void> {
		if (!revokeTarget) return;
		busy = true;
		failure = null;
		try {
			await revokeToken(revokeTarget.id);
			revokeTarget = null;
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}
</script>

{#if !isAdmin}
	<!-- Hidden entirely for viewers per SPEC navigation merge. -->
{:else if result.kind === 'loading'}
	<p class="state">{m.state_loading()}</p>
{:else if result.kind === 'unavailable'}
	<UnavailableNotice />
{:else if result.kind === 'error'}
	<ErrorNotice code={result.code} params={result.params} />
{:else}
	{#if plaintext}
		<div class="callout" role="status">
			<p class="callout-title">{m.token_plaintext_title()}</p>
			<p class="callout-body">{m.token_plaintext_body()}</p>
			<code class="mono token-value">{plaintext}</code>
			<div class="callout-actions">
				<Button onclick={() => void copyPlaintext()}>{m.action_copy()}</Button>
				<Button onclick={() => (plaintext = null)}>{m.action_close()}</Button>
			</div>
		</div>
	{/if}

	<div class="toolbar">
		<Button variant="primary" onclick={openCreate}>{m.token_create()}</Button>
	</div>

	<GroupedList header={m.settings_group_tokens()}>
		{#each result.data as token (token.id)}
			<GroupedRow
				label={displayText(token.name).text}
				detail={`${scopeLabel(token.scope)} · ${formatDateTime(new Date(token.created_at), locale)}`}
			>
				{#snippet trailing()}
					<Button variant="danger" onclick={() => (revokeTarget = token)}>
						{m.token_revoke()}
					</Button>
				{/snippet}
			</GroupedRow>
		{:else}
			<GroupedRow label={m.token_empty()} />
		{/each}
	</GroupedList>
{/if}

{#if sheetOpen}
	<Sheet open={true} title={m.token_create_title()} onclose={() => (sheetOpen = false)}>
		<label class="field-label" for="token-name">{m.token_name_label()}</label>
		<input id="token-name" class="field" bind:value={formName} autocomplete="off" />

		<p class="field-label">{m.token_scope_label()}</p>
		<div class="scopes">
			{#each scopeOptions as option (option.value)}
				<label class="scope-row">
					<input type="radio" name="token-scope" value={option.value} bind:group={formScope} />
					{option.label()}
				</label>
			{/each}
		</div>

		{#if selfSigned && (formScope === 'mcp:read' || formScope === 'mcp:write')}
			<Banner title={m.token_self_signed_banner_title()}>
				<p>{m.token_self_signed_banner_body()}</p>
			</Banner>
			<label class="confirm-row">
				<Switch bind:checked={confirmSelfSigned} aria-label={m.token_self_signed_confirm_label()} />
				<span>{m.token_self_signed_confirm_label()}</span>
			</label>
		{/if}

		{#if failure}
			<div class="notice">
				{#if failure.code === 'settings_token_self_signed_required'}
					<p>{m.token_self_signed_confirm_required()}</p>
				{:else}
					<ErrorNotice code={failure.code} params={failure.params} />
				{/if}
			</div>
		{/if}

		<div class="actions">
			<Button onclick={() => (sheetOpen = false)}>{m.action_cancel()}</Button>
			<Button variant="primary" disabled={busy || formName.trim() === ''} onclick={submitCreate}>
				{m.token_create_confirm()}
			</Button>
		</div>
	</Sheet>
{/if}

{#if revokeTarget}
	<Sheet open={true} title={m.token_revoke_title()} onclose={() => (revokeTarget = null)}>
		<p class="body">{m.token_revoke_body({ name: displayText(revokeTarget.name).text })}</p>
		{#if failure}
			<div class="notice">
				<ErrorNotice code={failure.code} params={failure.params} />
			</div>
		{/if}
		<div class="actions">
			<Button onclick={() => (revokeTarget = null)}>{m.action_cancel()}</Button>
			<Button variant="danger" disabled={busy} onclick={confirmRevoke}>
				{m.token_revoke_confirm()}
			</Button>
		</div>
	</Sheet>
{/if}

<style>
	.toolbar {
		margin-bottom: 0.75rem;
	}

	.state {
		margin: 0;
		color: var(--label-2);
	}

	.confirm-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		min-height: 2.75rem;
		margin: 0.75rem 0;
	}

	.callout {
		margin-bottom: 1rem;
		padding: 0.875rem 1rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
	}

	.callout-title {
		margin: 0 0 0.25rem;
		font-weight: 600;
	}

	.callout-body {
		margin: 0 0 0.75rem;
		color: var(--label-2);
		font-size: 0.84375rem;
	}

	.token-value {
		display: block;
		padding: 0.5rem;
		overflow-x: auto;
		word-break: break-all;
		background: var(--surface-2);
		border-radius: var(--r-control);
	}

	.callout-actions {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin-top: 0.75rem;
	}

	.field-label {
		display: block;
		margin: 0 0 0.375rem;
		font-size: 0.84375rem;
		color: var(--label-2);
	}

	.field {
		width: 100%;
		min-height: 2.75rem;
		margin-bottom: 1rem;
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		color: var(--label);
	}

	.scopes {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		margin-bottom: 1rem;
	}

	.scope-row {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		min-height: 2.75rem;
	}

	.notice {
		margin: 0.75rem 0;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.5rem;
		margin-top: 1rem;
	}

	.body {
		margin: 0;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
</style>
