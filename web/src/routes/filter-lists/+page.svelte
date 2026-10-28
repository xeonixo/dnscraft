<script lang="ts">
	import { onMount } from 'svelte';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		deleteFilterList,
		listFilterLists,
		listFilterSets,
		saveFilterList,
		type FilterList,
		type FilterSet,
	} from '$lib/api/filtering';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { formatDateTime, formatNumber, formatRelativeTime } from '$lib/format';
	import { errorMessage, getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';
	import { displayText } from '$lib/safe-text';

	type Failure = { code: string; params: Record<string, unknown> };

	/** Updates older than this show their date instead of "x days ago". */
	const RELATIVE_LIMIT_MS = 7 * 86_400_000;
	/** Filter set names shown per list before the rest are counted. */
	const USER_PREVIEW = 3;

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<FilterList[]>>({ kind: 'loading' });
	/** Filter sets for the "used by" line; null when they did not load (the line is then left out). */
	let sets = $state<FilterSet[] | null>(null);
	let sheetOpen = $state(false);
	let editing = $state<FilterList | null>(null);
	let busy = $state(false);
	let failure = $state<Failure | null>(null);
	let confirmDelete = $state(false);
	let togglingId = $state<string | null>(null);
	let toggleFailure = $state<Failure | null>(null);
	let formId = $state('');
	let formName = $state('');
	let formUrl = $state('');
	let formEnabled = $state(true);

	const rows = $derived(result.kind === 'ok' ? result.data : []);
	/** Enabled lists with a successful build; their rule counts make up the total. */
	const active = $derived(rows.filter((list) => list.enabled && list.status?.last_success));
	const totalRules = $derived(
		active.reduce((sum, list) => sum + (list.status?.rules_parsed ?? 0), 0),
	);
	const totalLine = $derived.by(() => {
		if (active.length === 0) return null;
		const locale = getLocale();
		const count = formatNumber(active.length, locale);
		const rules = formatNumber(totalRules, locale);
		return active.length === 1
			? m.filter_lists_total_one({ rules, count })
			: m.filter_lists_total_other({ rules, count });
	});

	/** Enabled lists whose last fetch failed; their rules still count in the total (from the last good build). */
	const failedCount = $derived(
		rows.filter((list) => list.enabled && list.status?.error_code).length,
	);

	function rulesText(count: number): string {
		const value = formatNumber(count, getLocale());
		return count === 1
			? m.filter_sets_count_rules_one({ count: value })
			: m.filter_sets_count_rules_other({ count: value });
	}

	/** The host of a URL source (the full URL stays in the edit sheet), or the file path. */
	function sourceLabel(list: FilterList): string {
		const { url, file } = list.source;
		if (url) {
			try {
				return displayText(new URL(url).host, 120).text;
			} catch {
				// Not a parseable URL: show it as stored, neutralised.
				return displayText(url, 120).text;
			}
		}
		return displayText(file ?? '', 120).text || m.querylog_none();
	}

	function updatedAt(iso: string | null): string | null {
		if (!iso) return null;
		const when = new Date(iso);
		if (Number.isNaN(when.getTime())) return null;
		const now = new Date();
		const locale = getLocale();
		return now.getTime() - when.getTime() > RELATIVE_LIMIT_MS
			? formatDateTime(when, locale)
			: formatRelativeTime(when, now, locale);
	}

	function usedByLine(list: FilterList): string | null {
		if (sets === null) return null;
		const users = sets.filter((set) => set.lists.includes(list.id));
		if (users.length === 0) return m.filter_lists_used_by_none();
		const names = users
			.slice(0, USER_PREVIEW)
			.map((set) => displayText(set.name || set.id, 60).text);
		const more = users.length - names.length;
		const line = m.filter_lists_used_by({ sets: names.join(', ') });
		return more > 0 ? `${line} ${m.filter_sets_used_by_more({ count: more })}` : line;
	}

	/** The body the API expects: never the engine status, which the server rejects on write. */
	function bodyOf(list: FilterList, enabled: boolean): FilterList {
		const source =
			list.source.url !== undefined ? { url: list.source.url } : { file: list.source.file };
		return { id: list.id, name: list.name, source, enabled };
	}

	async function load(): Promise<void> {
		result = await settle(listFilterLists());
	}

	/** Filter sets are an admin read; any failure just leaves the usage line off the rows. */
	async function loadSets(): Promise<void> {
		try {
			sets = await listFilterSets();
		} catch {
			sets = null;
		}
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formName = '';
		formUrl = '';
		formEnabled = true;
		confirmDelete = false;
		failure = null;
		sheetOpen = true;
	}

	function openEdit(list: FilterList): void {
		editing = list;
		formId = list.id;
		formName = list.name;
		formUrl = list.source.url ?? list.source.file ?? '';
		formEnabled = list.enabled;
		confirmDelete = false;
		failure = null;
		sheetOpen = true;
	}

	function closeSheet(): void {
		sheetOpen = false;
		confirmDelete = false;
	}

	async function submit(): Promise<void> {
		busy = true;
		const id = editing?.id ?? formId.trim();
		const source = formUrl.startsWith('http') ? { url: formUrl.trim() } : { file: formUrl.trim() };
		try {
			await saveFilterList({ id, name: formName, source, enabled: formEnabled });
			closeSheet();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeList(): Promise<void> {
		if (!editing) return;
		busy = true;
		try {
			await deleteFilterList(editing.id);
			closeSheet();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	/** Enables or disables a list in place; the switch is put back if the save fails. */
	async function toggle(list: FilterList, input: HTMLInputElement): Promise<void> {
		const enabled = input.checked;
		togglingId = list.id;
		toggleFailure = null;
		try {
			await saveFilterList(bodyOf(list, enabled));
			await load();
		} catch (cause) {
			input.checked = !enabled;
			toggleFailure = failureOf(cause);
		} finally {
			togglingId = null;
		}
	}

	onMount(() => {
		void load();
		if (isAdmin) void loadSets();
	});
</script>

<div class="filter-lists">
	<div class="page-head">
		<p class="lead">{m.filter_lists_lead()}</p>
		{#if isAdmin}
			<Button variant="primary" onclick={openCreate}>{m.filter_lists_add()}</Button>
		{/if}
	</div>

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void load()} />
	{:else}
		<Banner title={m.filter_lists_refresh_unavailable()} />

		{#if totalLine}
			<p class="total">
				<span>{totalLine}</span>{#if failedCount > 0}<span class="muted">
						· {m.filter_lists_failed_last_update({
							count: formatNumber(failedCount, getLocale()),
						})}</span
					>{/if}
			</p>
		{/if}
		{#if toggleFailure}
			<ErrorNotice code={toggleFailure.code} params={toggleFailure.params} />
		{/if}

		{#snippet statusBlock(list: FilterList)}
			{#if !list.enabled}
				<span class="line muted">
					<Icon name="x-circle" size="0.875rem" />
					{m.filter_list_disabled()}
				</span>
			{:else if !list.status || (list.status.last_success === null && !list.status.error_code)}
				<span class="line muted">
					<Icon name="help-circle" size="0.875rem" />
					{m.filter_lists_status_pending()}
				</span>
			{:else}
				{#if list.status.last_success !== null}
					<span class="line">
						{rulesText(list.status.rules_parsed)}
						{#if list.status.rules_skipped > 0}
							<span class="muted">
								· {m.filter_lists_status_skipped({
									count: formatNumber(list.status.rules_skipped, getLocale()),
								})}
							</span>
						{/if}
					</span>
				{/if}
				{#if list.status.error_code}
					<span class="line failed">
						<Icon name="alert-triangle" size="0.875rem" strokeWidth={1.8} />
						{m.filter_lists_status_failed()}: {errorMessage(list.status.error_code)}
						{#if list.status.http_status !== null}
							<span class="muted">
								({m.filter_lists_status_http({ status: String(list.status.http_status) })})
							</span>
						{/if}
					</span>
				{:else if updatedAt(list.status.last_success)}
					<span class="line muted">
						{m.filter_lists_status_updated({ when: updatedAt(list.status.last_success) ?? '' })}
					</span>
				{/if}
			{/if}
		{/snippet}

		<GroupedList>
			{#each rows as list (list.id)}
				{@const name = displayText(list.name || list.id).text}
				<div class="list-row">
					<div class="main">
						<span class="name">{name}</span>
						<span class="host">{sourceLabel(list)}</span>
						{@render statusBlock(list)}
						{#if sets !== null}
							<span class="muted">{usedByLine(list)}</span>
						{/if}
					</div>
					<div class="trailing">
						{#if isAdmin}
							<Switch
								checked={list.enabled}
								disabled={togglingId === list.id}
								aria-label={m.filter_lists_toggle_label({ name })}
								onchange={(event) => void toggle(list, event.currentTarget)}
							/>
						{:else if list.enabled}
							<span class="state-text">{m.filter_list_enabled()}</span>
						{/if}
					</div>
					{#if isAdmin}
						<button
							type="button"
							class="row-edit"
							aria-label={m.action_edit()}
							onclick={() => openEdit(list)}
						>
							<Icon name="chevron-right" size="1rem" />
						</button>
					{/if}
				</div>
			{:else}
				<GroupedRow label={m.state_empty()} />
			{/each}
		</GroupedList>
	{/if}

	{#if sheetOpen && isAdmin}
		<Sheet
			open={sheetOpen}
			title={editing ? m.filter_lists_edit_title() : m.filter_lists_add_title()}
			onclose={closeSheet}
			centeredOnWide
		>
			{#if !editing}
				<label class="field-label" for="fl-id">{m.filter_lists_id_label()}</label>
				<input id="fl-id" class="field mono" bind:value={formId} />
			{/if}
			<label class="field-label" for="fl-name">{m.filter_lists_name_label()}</label>
			<input id="fl-name" class="field" bind:value={formName} />
			<label class="field-label" for="fl-source">{m.filter_lists_source_label()}</label>
			<input id="fl-source" class="field mono" bind:value={formUrl} />
			<div class="switch-row">
				<span>{m.filter_list_enabled()}</span>
				<Switch bind:checked={formEnabled} aria-label={m.filter_list_enabled()} />
			</div>

			{#snippet footer()}
				{#if failure}
					<div class="footer-error">
						<ErrorNotice code={failure.code} params={failure.params} />
					</div>
				{/if}
				{#if editing && confirmDelete}
					<p class="confirm-text">{m.filter_lists_delete_question()}</p>
					<div class="actions">
						<Button variant="secondary" onclick={() => (confirmDelete = false)}>
							{m.action_cancel()}
						</Button>
						<Button variant="danger" disabled={busy} onclick={() => void removeList()}>
							{m.action_delete()}
						</Button>
					</div>
				{:else}
					{#if editing}
						<button type="button" class="danger-text" onclick={() => (confirmDelete = true)}>
							{m.filter_lists_delete()}
						</button>
					{/if}
					<div class="actions">
						<Button variant="secondary" onclick={closeSheet}>{m.action_cancel()}</Button>
						<Button variant="primary" disabled={busy} onclick={() => void submit()}
							>{m.action_save()}</Button
						>
					</div>
				{/if}
			{/snippet}
		</Sheet>
	{/if}
</div>

<style>
	.filter-lists {
		max-width: 60rem;
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
	}
	.lead {
		max-width: 40rem;
		margin: 0;
		color: var(--label-2);
	}
	.state {
		color: var(--label-2);
	}
	.total .muted {
		font-weight: 400;
		color: var(--label-2);
	}
	.total {
		margin: 0;
		font-weight: 500;
	}
	.list-row {
		position: relative;
		display: flex;
		align-items: center;
		gap: var(--space-3);
		min-height: var(--control-h);
		padding: var(--space-3) var(--space-4);
	}
	.main {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}
	.name {
		font-weight: 600;
		overflow-wrap: anywhere;
	}
	.host {
		font-family: var(--font-mono);
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.line {
		display: block;
		font-size: 0.8125rem;
	}
	.line :global(svg) {
		margin-inline-end: 0.25rem;
		vertical-align: -0.15em;
	}
	.muted {
		color: var(--label-2);
	}
	.main > .muted {
		font-size: 0.8125rem;
	}
	.failed {
		color: var(--danger);
		font-weight: 500;
	}
	.trailing {
		display: flex;
		flex: 0 0 auto;
		align-items: center;
	}
	.state-text {
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.row-edit {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 2.25rem;
		min-height: var(--control-h);
		padding: 0;
		border: none;
		background: transparent;
		color: var(--label-3);
		cursor: pointer;
	}
	/* The row keeps the hairline and hover of the grouped list; the edit control is its own target. */
	.list-row:hover {
		background: var(--surface-2);
	}
	.field-label {
		display: block;
		margin: 0.75rem 0 0.25rem;
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.field {
		width: 100%;
		min-height: var(--control-h);
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font: inherit;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		min-height: var(--control-h);
	}
	.danger-text {
		align-self: flex-start;
		min-height: var(--control-h);
		padding: 0 0.25rem;
		border: none;
		background: transparent;
		color: var(--danger);
		font: inherit;
		font-weight: 500;
		cursor: pointer;
	}
	.footer-error {
		flex: 0 0 100%;
	}
	.confirm-text {
		flex: 0 0 100%;
		margin: 0;
		color: var(--label);
	}
	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: var(--space-2);
		margin-inline-start: auto;
	}
</style>
