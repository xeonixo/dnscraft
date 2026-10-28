<script lang="ts">
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import type { Pathname } from '$app/types';
	import { ApiError } from '$lib/api/client';
	import { oidcAuthorizeUrl } from '$lib/api/auth';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import { takeReturnTo, auth } from '$lib/auth/state.svelte';
	import { loadMe, loginLocal } from '$lib/auth/store.svelte';
	import LocaleSwitcher from '$lib/i18n/LocaleSwitcher.svelte';
	import { CLIENT_NETWORK } from '$lib/api/error-codes';
	import { m } from '$lib/paraglide/messages';
	import { setTheme, theme, type ThemeChoice } from '$lib/theme';

	interface Failure {
		code: string;
		params: Record<string, unknown>;
	}

	const LOCKED = 'control_api.auth.locked';

	let username = $state('');
	let password = $state('');
	let submitting = $state(false);
	let localFailure = $state<Failure | null>(null);
	let oidcFailure = $state<Failure | null>(null);

	const lockedOut = $derived(localFailure?.code === LOCKED);
	const retrySeconds = $derived(
		typeof localFailure?.params.retry_after === 'number' ? localFailure.params.retry_after : null,
	);

	const themeOptions: { value: ThemeChoice; label: string }[] = [
		{ value: 'system', label: m.theme_system() },
		{ value: 'light', label: m.theme_light() },
		{ value: 'dark', label: m.theme_dark() },
	];

	function failureOf(error: unknown): Failure {
		if (error instanceof ApiError) return { code: error.code, params: error.params };
		return { code: CLIENT_NETWORK, params: {} };
	}

	// The password is sent once and cleared on every outcome; it is never logged or stored.
	async function signIn(event: SubmitEvent): Promise<void> {
		event.preventDefault();
		if (submitting || lockedOut) return;
		submitting = true;
		localFailure = null;
		try {
			await loginLocal(username, password);
			await loadMe();
			if (auth.status === 'authenticated') {
				// takeReturnTo() already validated the value as a same-origin path outside the public routes.
				// The resolver's route union is too large for TypeScript to match that path, so its argument
				// tuple is passed as the resolver's own parameter type.
				const target = (takeReturnTo() ?? '/dashboard') as Pathname;
				const args = [target] as Parameters<typeof resolve>;
				await goto(resolve(...args), { replaceState: true });
			}
		} catch (error) {
			localFailure = failureOf(error);
		} finally {
			password = '';
			submitting = false;
		}
	}

	async function signInWithOidc(): Promise<void> {
		if (submitting) return;
		submitting = true;
		oidcFailure = null;
		try {
			// Stays busy while the browser leaves for the identity provider.
			globalThis.location.assign(await oidcAuthorizeUrl());
		} catch (error) {
			oidcFailure = failureOf(error);
			submitting = false;
		}
	}
</script>

<svelte:head>
	<title>{m.document_title({ page: m.login_title(), app: m.app_name() })}</title>
</svelte:head>

<main class="login">
	<header class="intro">
		<h1>{m.login_title()}</h1>
		<p>{m.login_lead()}</p>
	</header>

	<div class="prefs">
		<LocaleSwitcher />
		<Segmented
			options={themeOptions}
			value={$theme}
			label={m.theme_group_label()}
			onchange={(choice) => setTheme(choice)}
		/>
	</div>

	<GroupedList header={m.login_oidc_section()}>
		<div class="row full">
			<Button variant="primary" onclick={signInWithOidc} disabled={submitting}>
				{m.login_oidc_button()}
			</Button>
		</div>
		{#if oidcFailure}
			<div class="row">
				<ErrorNotice code={oidcFailure.code} params={oidcFailure.params} onretry={signInWithOidc} />
			</div>
		{/if}
	</GroupedList>

	<GroupedList header={m.login_local_section()} footer={m.login_local_footer()}>
		<form class="row form" onsubmit={signIn}>
			{#if lockedOut}
				<div class="lockout" role="alert">
					<p>{m.login_locked_window()}</p>
					{#if retrySeconds !== null}
						<p>{m.login_locked_retry({ seconds: String(retrySeconds) })}</p>
					{/if}
					<Button onclick={() => (localFailure = null)}>{m.action_retry()}</Button>
				</div>
			{:else if localFailure}
				<ErrorNotice code={localFailure.code} params={localFailure.params} />
			{/if}

			<label class="field">
				<span>{m.login_username_label()}</span>
				<input
					name="username"
					autocomplete="username"
					autocapitalize="none"
					spellcheck="false"
					required
					bind:value={username}
					disabled={submitting}
				/>
			</label>

			<label class="field">
				<span>{m.login_password_label()}</span>
				<input
					type="password"
					name="password"
					autocomplete="current-password"
					required
					bind:value={password}
					disabled={submitting}
				/>
			</label>

			<Button type="submit" variant="primary" disabled={submitting || lockedOut}>
				{submitting ? m.login_submitting() : m.login_submit()}
			</Button>
		</form>
	</GroupedList>
</main>

<style>
	.login {
		display: flex;
		flex-direction: column;
		gap: var(--space-5);
		box-sizing: border-box;
		width: 100%;
		max-width: 27.5rem;
		min-height: 100dvh;
		margin: 0 auto;
		padding: var(--space-6) var(--space-4);
		justify-content: center;
	}

	.intro h1 {
		margin: 0 0 var(--space-2);
		font-size: 1.75rem;
		font-weight: 700;
		letter-spacing: -0.02em;
		color: var(--label);
	}

	.intro p {
		margin: 0;
		color: var(--label-2);
	}

	.prefs {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
	}

	.row {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: var(--space-4);
	}

	.full :global(.btn),
	.form :global(.btn) {
		width: 100%;
	}

	.form {
		align-items: stretch;
	}

	.lockout {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--warn-fill);
		color: var(--label);
	}

	.lockout p {
		margin: 0;
		overflow-wrap: anywhere;
	}

	.lockout :global(.btn) {
		align-self: flex-start;
	}

	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		font-size: 0.875rem;
		color: var(--label-2);
	}

	input {
		box-sizing: border-box;
		width: 100%;
		min-height: 2.75rem;
		padding: var(--space-2) var(--space-3);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface-2);
		color: var(--label);
		font: inherit;
		font-size: 1rem;
	}

	input:disabled {
		opacity: 0.6;
	}
</style>
