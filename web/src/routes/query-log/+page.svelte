<script lang="ts">
	import { onMount, untrack } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import Banner from '$lib/components/Banner.svelte';
	import Button from '$lib/components/Button.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { exportHref, listQueryLog, type QueryPage } from '$lib/api/query-log';
	import { openQueryLogStream } from '$lib/api/query-log-stream';
	import { settle, type Result } from '$lib/api/result';
	import { getOverview, type StatsOverview } from '$lib/api/stats';
	import ActiveTags from '$lib/querylog/ActiveTags.svelte';
	import FilterForm from '$lib/querylog/FilterForm.svelte';
	import QueryCards from '$lib/querylog/QueryCards.svelte';
	import QueryTable from '$lib/querylog/QueryTable.svelte';
	import {
		DEFAULT_PERIOD,
		INVALID_CODE,
		draftFromSearch,
		emptyDraft,
		fieldForReason,
		pageOf,
		patchDraft,
		toApiParams,
		toSearchParams,
		validateDraft,
		type Draft,
		type FieldErrors,
		type FilterKey,
	} from '$lib/querylog/filters';
	import { isLiveHead, mergeLivePage, streamHref } from '$lib/querylog/live';
	import { mediaMatches, WIDE_QUERY } from '$lib/querylog/media';
	import {
		readDensity,
		readTechnical,
		writeDensity,
		writeTechnical,
		type Density,
	} from '$lib/querylog/density';
	import {
		listHref,
		readSaved,
		withSaved,
		writeLast,
		writeSaved,
		type SavedFilter,
	} from '$lib/querylog/saved';
	import { formatNumber } from '$lib/format';
	import { getLocale } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';

	const locale = getLocale();
	/** Control-api code for a rejected paging value (`limit` or `offset`). */
	const PAGINATION_CODE = 'control_api.pagination.invalid';
	const SEARCH_DEBOUNCE_MS = 300;

	const densityOptions: { value: Density; label: string }[] = [
		{ value: 'comfortable', label: m.querylog_density_comfortable() },
		{ value: 'compact', label: m.querylog_density_compact() },
	];
	const statusOptions = $derived<{ value: string; label: string }[]>([
		{ value: 'all', label: m.querylog_all() },
		{ value: 'allowed', label: m.querylog_status_allowed() },
		{ value: 'blocked', label: m.querylog_status_blocked() },
	]);
	const periodOptions = $derived<{ value: string; label: string }[]>([
		{ value: '15m', label: m.period_15m() },
		{ value: '1h', label: m.period_1h() },
		{ value: '24h', label: m.period_24h() },
		{ value: '7d', label: m.period_7d() },
		{ value: '30d', label: m.period_30d() },
		{ value: 'custom', label: m.querylog_range_custom() },
	]);

	// The URL is the source of truth for every filter; everything below derives from it.
	const draft = $derived(draftFromSearch(page.url.searchParams));
	const urlErrors = $derived(validateDraft(draft));
	const invalid = $derived(Object.keys(urlErrors).length > 0);
	const query = $derived(toApiParams(draft));
	const pager = $derived(pageOf(draft));

	let result = $state<Result<QueryPage>>({ kind: 'loading' });
	let overview = $state<Result<StatsOverview>>({ kind: 'loading' });
	let wide = $state(mediaMatches(WIDE_QUERY));
	let density = $state<Density>(readDensity());
	let technical = $state(readTechnical());
	let filterOpen = $state(false);
	let searchText = $state('');
	let saved = $state<SavedFilter[]>(readSaved());
	/** The last value this page wrote to the URL; the URL echoing it back must not touch the box. */
	let lastWritten: string | undefined;
	let searchTimer: ReturnType<typeof setTimeout> | undefined;
	let runs = 0;
	/** Bumped by Retry: the same URL must still fetch again. */
	let attempt = $state(0);
	/** Extra drops reported by the live SSE `lagged` event (WX2). */
	let streamDropped = $state(0);
	const loaded = $derived(result.kind === 'ok' ? result.data : null);

	/** A server-rejected filter or page value, mapped back to the field that caused it. */
	const serverErrors = $derived.by<FieldErrors>(() => {
		if (result.kind !== 'error') return {};
		if (result.code !== INVALID_CODE && result.code !== PAGINATION_CODE) return {};
		const reason = typeof result.params.reason === 'string' ? result.params.reason : '';
		const field = fieldForReason(reason);
		return field ? { [field]: result.code } : {};
	});
	const formErrors = $derived<FieldErrors>({ ...urlErrors, ...serverErrors });
	const unmappedError = $derived(
		result.kind === 'error' && Object.keys(serverErrors).length === 0 ? result : null,
	);
	const dropped = $derived(
		(overview.kind === 'ok' ? overview.data.query_log_dropped : 0) + streamDropped,
	);

	// Loads the list for the current URL. A newer run makes an older response obsolete.
	$effect(() => {
		const params = query;
		void attempt;
		if (invalid) return;
		const run = ++runs;
		void settle(listQueryLog(params)).then((next) => {
			if (run === runs) result = next;
		});
	});

	// Always-on live tail (WX2): no toggle. Prepends onto the first page when sorted newest-first.
	$effect(() => {
		if (invalid) return;
		const href = streamHref(query);
		const merge = isLiveHead(draft);
		streamDropped = 0;
		const stream = openQueryLogStream(href, {
			onRow(row) {
				if (!merge) return;
				if (result.kind !== 'ok') return;
				result = { kind: 'ok', data: mergeLivePage(result.data, [row]) };
			},
			onLagged(count) {
				streamDropped += count;
			},
		});
		return () => stream.stop();
	});

	// Keeps the search box in step with the URL, but not while the user is typing.
	$effect(() => {
		const fromUrl = draft.domain_substr;
		untrack(() => {
			if (fromUrl === lastWritten) return;
			lastWritten = undefined;
			if (fromUrl !== searchText.trim()) searchText = fromUrl;
		});
	});

	// Remembers the shown filters for the detail page's back link.
	$effect(() => writeLast(page.url.search.replace(/^\?/, '')));

	async function loadOverview(): Promise<void> {
		overview = await settle(getOverview('24h'));
	}

	onMount(() => {
		void loadOverview();
		const media = globalThis.matchMedia?.(WIDE_QUERY);
		const onChange = (event: MediaQueryListEvent): void => {
			wide = event.matches;
		};
		media?.addEventListener('change', onChange);
		return () => {
			media?.removeEventListener('change', onChange);
			clearTimeout(searchTimer);
		};
	});

	/** Writes the draft to the URL. Replaces the history entry: filter changes are not navigation. */
	function writeUrl(next: Draft): void {
		const search = toSearchParams(next).toString();
		const target = search === '' ? resolve('/query-log') : resolve(`/query-log?${search}`);
		void goto(target, { replaceState: true, noScroll: true, keepFocus: true });
	}

	function onSearch(value: string): void {
		searchText = value;
		clearTimeout(searchTimer);
		searchTimer = setTimeout(() => {
			lastWritten = value.trim();
			writeUrl(patchDraft(draft, { domain_substr: value }));
		}, SEARCH_DEBOUNCE_MS);
	}

	let saveName = $state('');

	function saveCurrent(event: SubmitEvent): void {
		event.preventDefault();
		const name = saveName.trim();
		if (name === '') return;
		saved = withSaved(saved, { name, search: toSearchParams(draft).toString() });
		writeSaved(saved);
		saveName = '';
		(event.currentTarget as HTMLElement).closest('details')?.removeAttribute('open');
	}

	function deleteSaved(name: string): void {
		saved = saved.filter((x) => x.name !== name);
		writeSaved(saved);
	}

	function applyFromSheet(next: Draft): void {
		filterOpen = false;
		writeUrl(next);
	}

	function setPeriod(value: string): void {
		if (value === DEFAULT_PERIOD) writeUrl(patchDraft(draft, { period: '', from: '', to: '' }));
		else if (value === 'custom') {
			writeUrl(patchDraft(draft, { period: 'custom' }));
			filterOpen = true;
		} else writeUrl(patchDraft(draft, { period: value, from: '', to: '' }));
	}

	function setStatus(value: string): void {
		writeUrl(patchDraft(draft, { status: value === 'all' ? '' : value }));
	}

	function removeKeys(keys: FilterKey[]): void {
		const cleared = Object.fromEntries(keys.map((key) => [key, ''])) as Partial<Draft>;
		writeUrl(patchDraft(draft, cleared));
	}

	function clearAll(): void {
		filterOpen = false;
		writeUrl(emptyDraft());
	}

	function goToOffset(offset: number): void {
		writeUrl({ ...draft, offset: offset > 0 ? String(offset) : '' });
	}

	function chooseDensity(next: Density): void {
		density = next;
		writeDensity(next);
	}

	function chooseTechnical(on: boolean): void {
		technical = on;
		writeTechnical(on);
	}
</script>

<svelte:window
	onclick={(event) => {
		// A popup closes on any click outside it (opening one closes the other).
		for (const menu of document.querySelectorAll<HTMLDetailsElement>('.bar details[open]')) {
			if (!menu.contains(event.target as Node)) menu.open = false;
		}
	}}
	onkeydown={(event) => {
		if (event.key === 'Escape') {
			for (const menu of document.querySelectorAll<HTMLDetailsElement>('.bar details[open]')) {
				menu.open = false;
			}
		}
	}}
/>

{#if dropped > 0}
	<Banner title={m.querylog_dropped_title()}>
		<p>{m.querylog_dropped_body({ count: formatNumber(dropped, locale) })}</p>
	</Banner>
{/if}

<div class="bar">
	<div class="search">
		<input
			class="field"
			type="search"
			maxlength="253"
			autocomplete="off"
			autocapitalize="none"
			spellcheck="false"
			placeholder={m.querylog_search_placeholder()}
			aria-label={m.querylog_search_label()}
			value={searchText}
			oninput={(event) => onSearch(event.currentTarget.value)}
		/>
	</div>
	<Button aria-haspopup="dialog" aria-expanded={filterOpen} onclick={() => (filterOpen = true)}>
		{m.querylog_filter_open()}
	</Button>
	<details class="more">
		<summary>{m.querylog_saved_open()}</summary>
		<div class="menu">
			{#each saved as item (item.name)}
				<div class="saved-row">
					<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- listHref resolves -->
					<a href={listHref(item.search)}>{item.name}</a>
					<button
						type="button"
						class="del"
						aria-label={m.querylog_saved_delete({ name: item.name })}
						onclick={() => deleteSaved(item.name)}>×</button
					>
				</div>
			{:else}
				<p class="note">{m.querylog_saved_empty()}</p>
			{/each}
			<form class="save-row" onsubmit={saveCurrent}>
				<input
					class="field"
					maxlength="64"
					autocomplete="off"
					placeholder={m.querylog_saved_prompt()}
					aria-label={m.querylog_saved_prompt()}
					bind:value={saveName}
				/>
				<Button type="submit" disabled={saveName.trim() === ''}>{m.querylog_saved_save()}</Button>
			</form>
		</div>
	</details>
	<details class="more">
		<summary>{m.querylog_more()}</summary>
		<div class="menu">
			<a href={exportHref('ndjson', query)} rel="external" download>{m.querylog_export_ndjson()}</a>
			<a href={exportHref('csv', query)} rel="external" download>{m.querylog_export_csv()}</a>
			<div class="menu-density">
				<span class="label">{m.querylog_density_label()}</span>
				<Segmented
					options={densityOptions}
					value={density}
					label={m.querylog_density_label()}
					onchange={chooseDensity}
				/>
			</div>
			<div class="menu-toggle">
				<span class="label" id="querylog-technical-label">{m.querylog_technical_columns()}</span>
				<Switch
					checked={technical}
					aria-labelledby="querylog-technical-label"
					onchange={(event) => chooseTechnical(event.currentTarget.checked)}
				/>
			</div>
			<p class="note">{m.querylog_export_note()}</p>
		</div>
	</details>
</div>

<div class="quick">
	<Segmented
		options={statusOptions}
		value={draft.status || 'all'}
		label={m.querylog_status()}
		onchange={setStatus}
	/>
	<Segmented
		options={periodOptions}
		value={draft.period || (draft.from || draft.to ? 'custom' : DEFAULT_PERIOD)}
		label={m.querylog_range_label()}
		onchange={setPeriod}
	/>
</div>

<ActiveTags {draft} onremove={removeKeys} onclear={clearAll} />

{#if invalid}
	<GroupedList>
		<GroupedRow label={m.querylog_fix_filters()} />
	</GroupedList>
{:else if loaded}
	<p class="summary">
		{#if loaded.queries.length > 0}
			<span>
				{m.querylog_page_range({
					from: formatNumber(pager.offset + 1, locale),
					to: formatNumber(pager.offset + loaded.queries.length, locale),
				})}
			</span>
		{/if}
		<span>{loaded.has_more ? m.querylog_page_more() : m.querylog_page_end()}</span>
	</p>
	{#if loaded.queries.length === 0}
		<GroupedList>
			<GroupedRow label={m.querylog_empty()} />
		</GroupedList>
	{:else if wide}
		<QueryTable
			rows={loaded.queries}
			compact={density === 'compact'}
			{technical}
			clientSearch={(filter) => toSearchParams({ ...draft, ...filter, offset: '' }).toString()}
		/>
	{:else}
		<QueryCards rows={loaded.queries} {technical} />
	{/if}

	<nav class="pager" aria-label={m.querylog_pager_label()}>
		<Button disabled={pager.offset === 0} onclick={() => goToOffset(pager.offset - pager.limit)}>
			{m.querylog_prev()}
		</Button>
		<Button
			disabled={!loaded.has_more}
			onclick={() => goToOffset(loaded.next_offset ?? pager.offset + pager.limit)}
		>
			{m.querylog_next()}
		</Button>
	</nav>
	<p class="note">{m.querylog_ip_note()}</p>
{:else if unmappedError}
	<ResultNotice result={unmappedError} onretry={() => attempt++} />
{:else if result.kind === 'unavailable'}
	<ResultNotice {result} />
{:else}
	<ResultNotice result={{ kind: 'loading' }} />
{/if}

<Sheet open={filterOpen} title={m.querylog_filter_title()} onclose={() => (filterOpen = false)}>
	<FilterForm initial={draft} external={formErrors} onapply={applyFromSheet} onreset={clearAll} />
</Sheet>

<style>
	.bar {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.625rem;
	}

	.search {
		flex: 1 1 16rem;
		min-width: 0;
	}

	/* Compact: smaller controls, and the menus open full width under the row. */
	@media (max-width: 54.99rem) {
		.bar,
		.quick {
			--control-h: 2rem;
			--control-px: 0.625rem;
			font-size: 0.8125rem;
		}

		.bar {
			position: relative;
		}

		.bar .more {
			position: static;
		}

		.bar .menu {
			inset-inline: 0;
			width: auto;
		}
	}

	/* Compact: search on its own row, Filter and the more-menu share the second row. */
	@media (max-width: 54.99rem) {
		.search {
			flex-basis: 100%;
		}
	}

	.field {
		box-sizing: border-box;
		width: 100%;
		min-height: var(--control-h);
		padding: 0.5rem 0.75rem;
		background: var(--surface-2);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		color: var(--label);
		font: inherit;
		font-family: var(--font-mono);
		font-size: 0.875rem;
	}

	.more {
		position: relative;
	}

	.more summary {
		display: inline-flex;
		align-items: center;
		min-height: var(--control-h);
		padding: 0 var(--control-px);
		background: var(--surface-2);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		color: var(--label);
		font-weight: 500;
		cursor: pointer;
		list-style: none;
	}

	.menu {
		position: absolute;
		inset-inline-end: 0;
		z-index: 10;
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		width: 17rem;
		margin-top: 0.25rem;
		padding: 0.25rem;
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		box-shadow: var(--shadow-sheet);
	}

	.menu > a {
		display: flex;
		align-items: center;
		min-height: var(--control-h);
		padding: 0 0.75rem;
		color: var(--accent);
		text-decoration: none;
		border-radius: var(--r-ctl);
	}

	.menu > a:hover {
		background: var(--surface-2);
	}

	.save-row {
		display: flex;
		gap: 0.375rem;
		padding: 0.25rem;
	}

	.saved-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
	}

	.saved-row a {
		flex: 1;
		display: flex;
		align-items: center;
		min-height: var(--control-h);
		padding: 0 0.75rem;
		color: var(--accent);
		text-decoration: none;
		border-radius: var(--r-ctl);
		overflow: hidden;
		text-overflow: ellipsis;
	}

	.saved-row a:hover {
		background: var(--surface-2);
	}

	.del {
		min-width: var(--control-h);
		min-height: var(--control-h);
		background: none;
		border: 0;
		color: var(--label-2);
		font-size: 1.25rem;
		cursor: pointer;
	}

	.menu-density {
		display: flex;
		flex-direction: column;
		gap: 0.375rem;
		padding: 0.5rem 0.75rem;
	}

	.menu-toggle {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		padding: 0 0.75rem;
	}

	.label {
		font-size: 0.8125rem;
		color: var(--label-2);
	}

	.note {
		margin: 0;
		padding: 0 0.75rem 0.5rem;
		font-size: 0.8125rem;
		color: var(--label-3);
	}

	/* One row: the two groups sit side by side, or scroll sideways on narrow screens. The
	   padding keeps focus rings from being clipped by the scroll container. */
	.quick {
		display: flex;
		flex-wrap: nowrap;
		align-items: center;
		gap: 0.5rem 0.75rem;
		overflow-x: auto;
		padding: 0.25rem;
		margin: -0.25rem;
	}

	.quick :global(.segmented) {
		flex: 0 0 auto;
		max-width: none;
	}

	.summary {
		display: flex;
		flex-wrap: wrap;
		gap: 0.25rem 0.75rem;
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-2);
		font-variant-numeric: tabular-nums;
	}

	.pager {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
	}
</style>
