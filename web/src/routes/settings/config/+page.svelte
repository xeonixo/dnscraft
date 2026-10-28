<script lang="ts">
	import { onMount } from 'svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import CheckSheet from '$lib/config/CheckSheet.svelte';
	import RollbackSheet from '$lib/config/RollbackSheet.svelte';
	import {
		CONFIG_VERSION_CODE,
		getConfig,
		getVersions,
		rollbackConfig,
		saveConfig,
		validateConfig,
		type ConfigSnapshot,
		type ConfigVersion,
		type ValidateResult,
		type VersionPage,
	} from '$lib/api/config';
	import { ApiError } from '$lib/api/client';
	import { CLIENT_MALFORMED } from '$lib/api/error-codes';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import {
		isVersionConflict,
		mcpRuleChanges,
		parseConfigText,
		type McpRuleChange,
	} from '$lib/config/view';
	import { formatDateTime } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { announce } from '$lib/live.svelte';
	import { m } from '$lib/paraglide/messages';

	type Failure = { code: string; params: Record<string, unknown> };

	/** Versions per page in the version list. */
	const VERSION_PAGE = 50;
	const locale = getLocale();
	const isAdmin = $derived(auth.role === 'admin');
	const uid = $props.id();
	const editorId = `${uid}-editor`;
	const errorId = `${uid}-parse-error`;

	/** The stored snapshot as the screen last loaded it. */
	let snapshot = $state<Result<ConfigSnapshot>>({ kind: 'loading' });
	/** The editor content. A reload after a conflict moves it to keptText, never drops it. */
	let text = $state('');
	let keptText = $state<string | null>(null);
	let conflict = $state(false);

	/** The last dry run, with the content it was made for. Save stays blocked while that content has errors. */
	let checked = $state<{ text: string; result: ValidateResult; changes: McpRuleChange[] } | null>(
		null,
	);
	let checkSheetOpen = $state(false);
	let checkBusy = $state(false);
	let checkFailure = $state<Failure | null>(null);
	let saveBusy = $state(false);
	let saveFailure = $state<Failure | null>(null);

	let versionRows = $state<ConfigVersion[]>([]);
	let versionCurrent = $state<number | null>(null);
	let versionNext = $state<number | null>(null);
	let versionsStatus = $state<'loading' | 'ok' | 'error'>('loading');
	let versionsFailure = $state<Failure | null>(null);
	let rollbackTarget = $state<number | null>(null);
	let rollbackBusy = $state(false);
	let rollbackFailure = $state<Failure | null>(null);

	const loaded = $derived(snapshot.kind === 'ok' ? snapshot.data : null);
	const snapshotFailure = $derived(
		snapshot.kind === 'loading' || snapshot.kind === 'ok' ? null : failureFromResult(snapshot),
	);
	const parsed = $derived(parseConfigText(text));
	const saveBlocked = $derived(
		!parsed.ok || (checked !== null && checked.text === text && !checked.result.valid),
	);

	async function load(): Promise<void> {
		snapshot = { kind: 'loading' };
		const result = await settle(getConfig());
		snapshot = result;
		if (result.kind === 'ok') {
			text = JSON.stringify(result.data.config, null, 2) ?? 'null';
			checked = null;
		}
	}

	async function loadVersions(append: boolean): Promise<void> {
		const offset = append ? (versionNext ?? 0) : 0;
		const result = await settle(getVersions(VERSION_PAGE, offset));
		if (result.kind !== 'ok') {
			versionsStatus = 'error';
			versionsFailure = failureFromResult(result);
			return;
		}
		const page: VersionPage = result.data;
		versionCurrent = page.current_version;
		versionRows = append ? [...versionRows, ...page.versions] : page.versions;
		versionNext = page.next_offset;
		versionsStatus = 'ok';
		versionsFailure = null;
	}

	/** The code and params a screen shows for a read that did not return data. */
	function failureFromResult(result: Result<unknown>): Failure {
		if (result.kind === 'error') return { code: result.code, params: result.params };
		if (result.kind === 'unavailable') return { code: result.code, params: {} };
		return { code: CLIENT_MALFORMED, params: {} };
	}

	function reloadAll(): Promise<unknown> {
		return Promise.all([load(), loadVersions(false)]);
	}

	onMount(() => {
		// The shell only renders this screen for an authenticated principal; viewers get no data calls.
		if (isAdmin) void reloadAll();
	});

	async function check(): Promise<void> {
		const current = parsed;
		if (!current.ok || !loaded || checkBusy) return;
		const submitted = text;
		checkBusy = true;
		checkFailure = null;
		try {
			const result = await validateConfig(current.value, loaded.version);
			checked = {
				text: submitted,
				result,
				changes: mcpRuleChanges(loaded.config, current.value),
			};
			if (result.errors.some(isVersionConflict)) conflict = true;
			checkSheetOpen = true;
		} catch (cause) {
			checkFailure = failureOf(cause);
		} finally {
			checkBusy = false;
		}
	}

	async function save(): Promise<void> {
		const current = parsed;
		if (!current.ok || !loaded || saveBlocked || saveBusy) return;
		saveBusy = true;
		saveFailure = null;
		try {
			const result = await saveConfig(current.value, loaded.version);
			keptText = null;
			conflict = false;
			announce(m.config_saved({ version: result.version }));
			await reloadAll();
		} catch (cause) {
			if (cause instanceof ApiError && cause.code === CONFIG_VERSION_CODE) {
				conflict = true;
			} else {
				saveFailure = failureOf(cause);
			}
		} finally {
			saveBusy = false;
		}
	}

	/** Keeps the editor text aside, then loads the latest stored version. Nothing the user typed is discarded. */
	async function reloadAfterConflict(): Promise<void> {
		keptText = text;
		conflict = false;
		await reloadAll();
	}

	function restoreKept(): void {
		if (keptText === null) return;
		text = keptText;
		keptText = null;
		checked = null;
	}

	async function copyKept(): Promise<void> {
		if (keptText === null) return;
		try {
			await globalThis.navigator.clipboard.writeText(keptText);
			announce(m.action_copied());
		} catch {
			// Clipboard unavailable: the text stays selectable in the read-only field.
		}
	}

	async function importFile(event: Event): Promise<void> {
		const input = event.currentTarget as HTMLInputElement;
		const file = input.files?.[0];
		input.value = '';
		if (!file) return;
		// Loading never saves: the file is checked right away, and only Speichern writes it.
		text = await file.text();
		checked = null;
		saveFailure = null;
		announce(m.config_import_loaded());
		await check();
	}

	function exportConfig(): void {
		if (!loaded || loaded.config === null) return;
		const blob = new Blob([`${JSON.stringify(loaded.config, null, 2)}\n`], {
			type: 'application/json',
		});
		const url = URL.createObjectURL(blob);
		const link = document.createElement('a');
		link.href = url;
		link.download =
			loaded.version === null ? 'dnscraft-config.json' : `dnscraft-config-v${loaded.version}.json`;
		document.body.append(link);
		link.click();
		link.remove();
		setTimeout(() => URL.revokeObjectURL(url), 1_000);
	}

	function closeRollback(): void {
		rollbackTarget = null;
		rollbackFailure = null;
	}

	async function rollback(): Promise<void> {
		const target = rollbackTarget;
		if (target === null || rollbackBusy) return;
		rollbackBusy = true;
		rollbackFailure = null;
		try {
			const result = await rollbackConfig(target, loaded?.version ?? null);
			rollbackTarget = null;
			keptText = null;
			announce(m.config_rollback_done({ version: target, current: result.version }));
			await reloadAll();
		} catch (cause) {
			const failure = failureOf(cause);
			rollbackFailure = failure;
			if (failure.code === 'control_api.config.unknown_version') void loadVersions(false);
		} finally {
			rollbackBusy = false;
		}
	}

	function parseMessage(): string {
		if (parsed.ok) return '';
		if (parsed.reason === 'not_object') return m.config_not_object();
		if (parsed.line !== null && parsed.column !== null) {
			return m.config_parse_error({ line: parsed.line, column: parsed.column });
		}
		return m.config_parse_error_generic();
	}
</script>

<p class="lead">{m.config_lead()}</p>

{#if !isAdmin}
	<GroupedList>
		<p class="state">{m.config_viewer_only()}</p>
	</GroupedList>
{:else}
	<GroupedList header={m.config_section_editor()} footer={m.config_editor_footer()}>
		<div class="pad">
			{#if snapshot.kind === 'loading'}
				<p class="state">{m.state_loading()}</p>
			{:else if snapshotFailure}
				<ErrorNotice
					code={snapshotFailure.code}
					params={snapshotFailure.params}
					onretry={() => void load()}
				/>
			{:else if loaded}
				<p class="version">
					{loaded.version === null
						? m.config_version_none()
						: m.config_version_label({ version: loaded.version })}
				</p>

				{#if conflict}
					<div class="conflict" role="alert">
						<p class="title">{m.error_control_api_config_version()}</p>
						<p class="body">{m.config_conflict_body()}</p>
						<div class="actions">
							<Button variant="primary" onclick={() => void reloadAfterConflict()}
								>{m.config_reload()}</Button
							>
						</div>
					</div>
				{/if}

				<label class="field-label" for={editorId}>{m.config_editor_label()}</label>
				<textarea
					id={editorId}
					class="editor"
					spellcheck="false"
					autocapitalize="off"
					autocomplete="off"
					aria-invalid={parsed.ok ? undefined : 'true'}
					aria-describedby={parsed.ok ? undefined : errorId}
					bind:value={text}></textarea>
				{#if !parsed.ok}
					<p class="parse-error" id={errorId}>{parseMessage()}</p>
				{/if}

				{#if keptText !== null}
					<details class="kept" open>
						<summary>{m.config_kept_title()}</summary>
						<textarea class="editor" readonly aria-label={m.config_kept_title()} spellcheck="false"
							>{keptText}</textarea
						>
						<div class="actions">
							<Button onclick={() => void copyKept()}>{m.action_copy()}</Button>
							<Button onclick={restoreKept}>{m.config_restore_kept()}</Button>
						</div>
					</details>
				{/if}

				{#if checkFailure}
					<div class="notice">
						<ErrorNotice code={checkFailure.code} params={checkFailure.params} />
					</div>
				{/if}
				{#if saveFailure}
					<div class="notice">
						<ErrorNotice code={saveFailure.code} params={saveFailure.params} />
					</div>
				{/if}

				<div class="actions">
					<Button disabled={!parsed.ok || checkBusy} onclick={() => void check()}
						>{m.config_check()}</Button
					>
					<Button variant="primary" disabled={saveBlocked || saveBusy} onclick={() => void save()}
						>{m.action_save()}</Button
					>
				</div>
				{#if checked && checked.text === text}
					<p class="check-state">
						{checked.result.valid
							? m.config_check_ok()
							: m.config_check_errors({ count: checked.result.errors.length })}
					</p>
				{/if}
				{#if saveBlocked && parsed.ok}
					<p class="check-state">{m.config_save_blocked()}</p>
				{/if}
			{/if}
		</div>
	</GroupedList>

	<GroupedList header={m.config_section_versions()} footer={m.config_versions_footer()}>
		{#if versionsStatus === 'loading'}
			<p class="state">{m.state_loading()}</p>
		{:else if versionsStatus === 'error' && versionsFailure}
			<div class="pad">
				<ErrorNotice
					code={versionsFailure.code}
					params={versionsFailure.params}
					onretry={() => void loadVersions(false)}
				/>
			</div>
		{:else if versionRows.length === 0}
			<p class="state">{m.config_versions_empty()}</p>
		{:else}
			{#each versionRows as row (row.version)}
				<GroupedRow
					label={m.config_version_label({ version: row.version })}
					detail={m.config_version_saved({
						time: formatDateTime(new Date(row.created_at), locale),
					})}
				>
					{#snippet trailing()}
						{#if row.version === versionCurrent}
							<span class="tag">{m.config_version_current()}</span>
						{:else}
							<Button onclick={() => (rollbackTarget = row.version)}>{m.config_rollback()}</Button>
						{/if}
					{/snippet}
				</GroupedRow>
			{/each}
			{#if versionNext !== null}
				<div class="pad">
					<Button onclick={() => void loadVersions(true)}>{m.config_versions_more()}</Button>
				</div>
			{/if}
		{/if}
	</GroupedList>

	<GroupedList header={m.config_section_import_export()}>
		<GroupedRow label={m.config_export()} detail={m.config_export_detail()}>
			{#snippet trailing()}
				<Button disabled={!loaded || loaded.config === null} onclick={exportConfig}
					>{m.config_export()}</Button
				>
			{/snippet}
		</GroupedRow>
		<GroupedRow label={m.config_import_label()} detail={m.config_import_detail()}>
			{#snippet trailing()}
				<label class="file-button">
					<span>{m.config_import_choose()}</span>
					<input
						class="file-input"
						type="file"
						accept="application/json,.json"
						onchange={(event) => void importFile(event)}
					/>
				</label>
			{/snippet}
		</GroupedRow>
	</GroupedList>
{/if}

<GroupedList header={m.config_section_backups()} footer={m.config_backups_detail()}>
	<GroupedRow label={m.config_backups_label()} detail={m.config_backups_unavailable()} />
</GroupedList>

{#if checkSheetOpen && checked}
	<CheckSheet
		result={checked.result}
		mcpChanges={checked.changes}
		onclose={() => (checkSheetOpen = false)}
	/>
{/if}

{#if rollbackTarget !== null}
	<RollbackSheet
		version={rollbackTarget}
		busy={rollbackBusy}
		failure={rollbackFailure}
		onconfirm={() => void rollback()}
		onclose={closeRollback}
	/>
{/if}

<style>
	.lead {
		margin: 0;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.state {
		margin: 0;
		padding: 1rem;
		color: var(--label-2);
	}

	.pad {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
		padding: 1rem;
	}

	.version {
		margin: 0;
		font-weight: 600;
		color: var(--label);
	}

	.field-label {
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	/* Machine data: mono, scrolls inside its own region, the page never scrolls sideways. */
	.editor {
		box-sizing: border-box;
		width: 100%;
		min-height: 18rem;
		max-height: 60vh;
		padding: 0.75rem;
		overflow: auto;
		background: var(--surface-2);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		color: var(--label);
		font-family: var(--font-mono);
		font-size: 0.8125rem;
		line-height: 1.5;
		white-space: pre;
		tab-size: 2;
		resize: vertical;
	}

	.parse-error {
		margin: 0;
		color: var(--danger);
		font-size: 0.875rem;
		overflow-wrap: anywhere;
	}

	.check-state {
		margin: 0;
		font-size: 0.875rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}

	.conflict {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
		padding: 0.875rem;
		background: var(--warn-fill);
		border-radius: var(--r-ctl);
	}

	.conflict .title,
	.conflict .body {
		margin: 0;
		color: var(--label);
		overflow-wrap: anywhere;
	}

	.conflict .title {
		font-weight: 600;
	}

	.kept {
		display: flex;
		flex-direction: column;
		gap: 0.5rem;
	}

	.kept summary {
		min-height: 2.75rem;
		display: flex;
		align-items: center;
		color: var(--label);
		font-weight: 600;
		cursor: pointer;
	}

	.notice {
		margin: 0;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.625rem;
	}

	.tag {
		display: inline-flex;
		align-items: center;
		min-height: 2.75rem;
		padding: 0 0.625rem;
		color: var(--label-2);
		font-size: 0.8125rem;
	}

	.file-button {
		position: relative;
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 2.75rem;
		min-height: 2.75rem;
		padding: 0.4375rem 1rem;
		background: var(--surface-2);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		color: var(--label);
		font-size: 0.875rem;
		font-weight: 500;
		cursor: pointer;
	}

	.file-button:focus-within {
		outline: 2px solid var(--accent);
		outline-offset: 2px;
	}

	/* The native file input stays focusable and reachable, but is visually hidden behind the label. */
	.file-input {
		position: absolute;
		width: 1px;
		height: 1px;
		margin: -1px;
		overflow: hidden;
		clip: rect(0 0 0 0);
		white-space: nowrap;
		border: 0;
		padding: 0;
	}
</style>
