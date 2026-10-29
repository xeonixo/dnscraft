<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import Button from '$lib/components/Button.svelte';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Icon from '$lib/components/Icon.svelte';
	import ResultNotice from '$lib/components/ResultNotice.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Sheet from '$lib/components/Sheet.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import UnavailableNotice from '$lib/components/UnavailableNotice.svelte';
	import {
		buildRuleText,
		deleteFilterSet,
		listFilterLists,
		listFilterSets,
		saveFilterSet,
		type BlockMode,
		type FilterList,
		type FilterSet,
		type GuidedRule,
	} from '$lib/api/filtering';
	import { ID_PATTERN, listProfiles, type PolicyProfile } from '$lib/api/policy';
	import { failureOf, settle, type Result } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';
	import { countRules, parseRuleLine, ruleLines } from '$lib/policy/rule-lines';
	import { displayText } from '$lib/safe-text';

	type FormBlockMode = 'refused' | 'nxdomain' | 'null_ip' | 'custom';
	type Failure = { code: string; params: Record<string, unknown> };
	interface Plural {
		one: (inputs: { count: number }) => string;
		other: (inputs: { count: number }) => string;
	}
	interface RuleView {
		text: string;
		kind: 'allow' | 'block' | null;
		/** Parsed as a plain domain rule; otherwise the raw line is shown. */
		parsed: boolean;
	}

	/** List names shown on a card before the rest are counted. */
	const LIST_PREVIEW = 3;
	/** Profile names shown on a card before the rest are counted. */
	const PROFILE_PREVIEW = 3;
	/** The block mode a set gets unless changed; only other modes are shown on a card. */
	const DEFAULT_BLOCK_MODE = 'refused';

	const LISTS: Plural = {
		one: m.filter_sets_count_lists_one,
		other: m.filter_sets_count_lists_other,
	};
	const RULES: Plural = {
		one: m.filter_sets_count_rules_one,
		other: m.filter_sets_count_rules_other,
	};
	const SERVICES: Plural = {
		one: m.filter_sets_count_services_one,
		other: m.filter_sets_count_services_other,
	};

	const isAdmin = $derived(auth.role === 'admin');
	let result = $state<Result<FilterSet[]>>({ kind: 'loading' });
	let lists = $state<FilterList[]>([]);
	let listsFailure = $state<Failure | null>(null);
	/** Null until the admin profile load succeeds; then the card shows which profiles use a set. */
	let profiles = $state<PolicyProfile[] | null>(null);
	let sheetOpen = $state(false);
	let busy = $state(false);
	let failure = $state<Failure | null>(null);
	let editing = $state<FilterSet | null>(null);
	let confirmDelete = $state(false);
	let formId = $state('');
	let submitted = $state(false);
	const idError = $derived.by(() => {
		if (editing) return null;
		const id = formId.trim();
		if (id === '') return submitted ? m.field_id_required() : null;
		return ID_PATTERN.test(id) ? null : m.field_id_invalid();
	});
	let formName = $state('');
	let formBlockMode = $state<FormBlockMode>('refused');
	let formLists = $state<string[]>([]);
	let formRaw = $state('');
	let showRaw = $state(false);
	let ruleAction = $state<'block' | 'allow'>('block');
	let ruleDomain = $state('');
	let ruleSubs = $state(true);

	const rows = $derived(result.kind === 'ok' ? result.data : []);
	const actionOptions = $derived([
		{ value: 'block', label: m.filter_rule_block() },
		{ value: 'allow', label: m.filter_rule_allow() },
	]);
	const blockOptions = $derived<{ value: FormBlockMode; label: string }[]>([
		{ value: 'refused', label: m.filter_block_refused() },
		{ value: 'nxdomain', label: m.filter_block_nxdomain() },
		{ value: 'null_ip', label: m.filter_block_null() },
		...(typeof editing?.block_mode === 'object'
			? [{ value: 'custom' as const, label: m.filter_block_custom() }]
			: []),
	]);

	function plural(count: number, forms: Plural): string {
		return count === 1 ? forms.one({ count }) : forms.other({ count });
	}

	/** Shows a plain domain rule as its domain and kind; anything else stays the raw line. */
	function ruleView(raw: string): RuleView {
		const rule = parseRuleLine(raw);
		if (rule.kind === 'advanced') return { text: raw, kind: null, parsed: false };
		return { text: rule.domain, kind: rule.action, parsed: true };
	}

	function blockLabel(mode: BlockMode): string {
		if (mode === 'nxdomain') return m.filter_block_nxdomain();
		if (mode === 'null_ip') return m.filter_block_null();
		if (typeof mode === 'object') return m.filter_block_custom();
		return m.filter_block_refused();
	}

	/** Counts of the things a set holds; zero counts are left out, and an empty set says so. */
	function summaryOf(set: FilterSet): string {
		const rules = countRules(set.custom_rules);
		const parts = [
			set.lists.length > 0 ? plural(set.lists.length, LISTS) : '',
			rules > 0 ? plural(rules, RULES) : '',
			set.services.length > 0 ? plural(set.services.length, SERVICES) : '',
		].filter((part) => part !== '');
		return parts.length > 0 ? parts.join(' · ') : m.filter_sets_nothing_configured();
	}

	/** Names of the profiles that use a set, or null when the profile data is not loaded. */
	function usedByLine(setId: string): string | null {
		if (profiles === null) return null;
		const users = profiles.filter((profile) => profile.filter_set === setId).map((p) => p.id);
		if (users.length === 0) return m.filter_sets_used_by_none();
		const names = users.slice(0, PROFILE_PREVIEW).map((id) => displayText(id, 60).text);
		const more = users.length - names.length;
		const line = m.filter_sets_used_by({ profiles: names.join(', ') });
		return more > 0 ? `${line} ${m.filter_sets_used_by_more({ count: more })}` : line;
	}

	/** First few list names of a set (display names when the list catalogue has them, else the id). */
	function listsLine(set: FilterSet): string {
		const names = set.lists.slice(0, LIST_PREVIEW).map((id) => {
			const list = lists.find((item) => item.id === id);
			return displayText(list?.name || id, 60).text;
		});
		const more = set.lists.length - names.length;
		const line = names.join(', ');
		return more > 0 ? `${line} ${m.filter_sets_lists_more({ count: more })}` : line;
	}

	function servicesLine(ids: string[]): string {
		return ids.map((id) => displayText(id, 60).text).join(', ');
	}

	function sourceOf(list: FilterList): string {
		return displayText(list.source.url ?? list.source.file ?? '', 80).text;
	}

	async function load(): Promise<void> {
		result = await settle(listFilterSets());
	}

	/** Profiles are an admin read; any failure just leaves the usage line off the cards. */
	async function loadProfiles(): Promise<void> {
		try {
			profiles = await listProfiles();
		} catch {
			profiles = null;
		}
	}

	async function loadLists(): Promise<void> {
		listsFailure = null;
		try {
			lists = await listFilterLists();
		} catch (cause) {
			lists = [];
			listsFailure = failureOf(cause);
		}
	}

	function resetForm(): void {
		showRaw = false;
		confirmDelete = false;
		ruleDomain = '';
		ruleAction = 'block';
		ruleSubs = true;
		failure = null;
		submitted = false;
		sheetOpen = true;
		void loadLists();
	}

	function openCreate(): void {
		editing = null;
		formId = '';
		formName = '';
		formBlockMode = 'refused';
		formLists = [];
		formRaw = '';
		resetForm();
	}

	function openEdit(set: FilterSet): void {
		editing = set;
		formId = set.id;
		formName = set.name;
		formBlockMode =
			typeof set.block_mode === 'object'
				? 'custom'
				: set.block_mode === 'nxdomain' || set.block_mode === 'null_ip'
					? set.block_mode
					: 'refused';
		formLists = [...set.lists];
		formRaw = set.custom_rules;
		resetForm();
	}

	function closeSheet(): void {
		sheetOpen = false;
		confirmDelete = false;
	}

	function setListOn(id: string, on: boolean): void {
		formLists = on ? [...new Set([...formLists, id])] : formLists.filter((item) => item !== id);
	}

	function appendGuidedRule(): void {
		const domain = ruleDomain.trim();
		if (!domain) return;
		const rule: GuidedRule = {
			action: ruleAction,
			domain,
			include_subdomains: ruleSubs,
		};
		const line = buildRuleText(rule);
		formRaw = formRaw.trim() ? `${formRaw.trimEnd()}\n${line}` : line;
		ruleDomain = '';
	}

	function removeRule(index: number): void {
		formRaw = formRaw
			.split('\n')
			.filter((_, position) => position !== index)
			.join('\n');
	}

	async function submit(): Promise<void> {
		submitted = true;
		const id = editing?.id ?? formId.trim();
		if (!editing && !ID_PATTERN.test(id)) return;
		failure = null;
		busy = true;
		// "custom" means the stored custom IP is kept as it was; the form only offers the fixed modes.
		const blockMode: BlockMode =
			formBlockMode === 'custom' ? (editing?.block_mode ?? 'refused') : formBlockMode;
		try {
			await saveFilterSet({
				id,
				name: formName,
				lists: formLists,
				custom_rules: formRaw,
				services: editing?.services ?? [],
				block_mode: blockMode,
			});
			closeSheet();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	async function removeSet(id: string): Promise<void> {
		if (!id) return;
		busy = true;
		try {
			await deleteFilterSet(id);
			closeSheet();
			await load();
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
		void loadLists();
		if (isAdmin) void loadProfiles();
	});
</script>

<div class="filter-sets">
	<div class="page-head">
		<p class="lead">
			{m.filter_sets_intro()}
			<a href={resolve('/profiles')}>{m.nav_profiles()}</a>
			{m.filter_sets_intro_profiles()}
		</p>
		{#if isAdmin}
			<Button variant="primary" onclick={openCreate}>{m.filter_sets_add()}</Button>
		{/if}
	</div>

	{#if result.kind === 'loading'}
		<p class="state">{m.state_loading()}</p>
	{:else if result.kind === 'unavailable'}
		<UnavailableNotice />
	{:else if result.kind === 'error'}
		<ResultNotice {result} onretry={() => void load()} />
	{:else if rows.length === 0}
		<section class="empty">
			<p>{m.filter_sets_empty()}</p>
			{#if isAdmin}
				<Button variant="primary" onclick={openCreate}>{m.filter_sets_add()}</Button>
			{/if}
		</section>
	{:else}
		{#snippet cardBody(set: FilterSet)}
			<span class="card-main">
				<span class="card-name">{displayText(set.name || set.id).text}</span>
				<span class="card-detail">{summaryOf(set)}</span>
				{#if set.block_mode !== DEFAULT_BLOCK_MODE}
					<span class="card-tag"
						>{m.filter_sets_summary_mode({ mode: blockLabel(set.block_mode) })}</span
					>
				{/if}
				{#if set.lists.length > 0}
					<span class="card-lists">{listsLine(set)}</span>
				{/if}
				{#if profiles !== null}
					<span class="card-lists">{usedByLine(set.id)}</span>
				{/if}
			</span>
			{#if isAdmin}
				<span class="chev" aria-hidden="true"><Icon name="chevron-right" size="1rem" /></span>
			{/if}
		{/snippet}
		<ul class="sets">
			{#each rows as set (set.id)}
				<li>
					{#if isAdmin}
						<button type="button" class="set-card" onclick={() => openEdit(set)}>
							{@render cardBody(set)}
						</button>
					{:else}
						<div class="set-card">{@render cardBody(set)}</div>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}

	{#if sheetOpen && isAdmin}
		<Sheet
			open={sheetOpen}
			title={editing ? m.filter_sets_edit_title() : m.filter_sets_add_title()}
			onclose={closeSheet}
			centeredOnWide
		>
			<GroupedList header={m.filter_sets_section_settings()}>
				{#if !editing}
					<div class="field-row">
						<label class="field-label" for="fs-id">{m.filter_sets_id_label()}</label>
						<input
							id="fs-id"
							class="field mono"
							bind:value={formId}
							autocomplete="off"
							aria-invalid={idError ? 'true' : undefined}
							oninput={() => (failure = null)}
						/>
						{#if idError}<p class="error-text" role="alert">{idError}</p>{/if}
					</div>
				{/if}
				<div class="field-row">
					<label class="field-label" for="fs-name">{m.filter_sets_name_label()}</label>
					<input id="fs-name" class="field" bind:value={formName} />
				</div>
				<div class="field-row">
					<span class="field-label">{m.filter_sets_block_mode()}</span>
					<Segmented
						options={blockOptions}
						bind:value={formBlockMode}
						label={m.filter_sets_block_mode()}
					/>
				</div>
			</GroupedList>

			<GroupedList header={m.filter_sets_section_lists()}>
				{#if listsFailure}
					<div class="field-row">
						<ErrorNotice code={listsFailure.code} params={listsFailure.params} />
					</div>
				{:else if lists.length === 0}
					<GroupedRow label={m.filter_sets_no_lists()} />
				{:else}
					{#each lists as list (list.id)}
						{@const name = displayText(list.name || list.id).text}
						<GroupedRow label={name} detail={sourceOf(list)} detailMono truncate>
							{#snippet trailing()}
								<Switch
									checked={formLists.includes(list.id)}
									aria-label={name}
									onchange={(event) => setListOn(list.id, event.currentTarget.checked)}
								/>
							{/snippet}
						</GroupedRow>
					{/each}
				{/if}
				<GroupedRow label={m.filter_sets_manage_lists()} href="/filter-lists" />
			</GroupedList>

			<GroupedList header={m.filter_sets_section_rules()}>
				{#each ruleLines(formRaw) as rule (rule.index)}
					{@const view = ruleView(rule.text)}
					<GroupedRow label={displayText(view.text, 200).text} mono={!view.parsed} truncate>
						{#snippet leading()}
							{#if view.kind}
								<span class="rule-kind {view.kind}">
									<Icon
										name={view.kind === 'allow' ? 'check-circle' : 'ban'}
										size="1rem"
										strokeWidth={1.7}
									/>
									<span>
										{view.kind === 'allow'
											? m.filter_rule_kind_allow()
											: m.filter_rule_kind_block()}
									</span>
								</span>
							{/if}
						{/snippet}
						{#snippet trailing()}
							<button
								type="button"
								class="text-action"
								aria-label={m.filter_rule_remove_label({ rule: displayText(rule.text, 40).text })}
								onclick={() => removeRule(rule.index)}
							>
								{m.filter_rule_remove()}
							</button>
						{/snippet}
					</GroupedRow>
				{:else}
					<GroupedRow label={m.filter_sets_rules_none()} />
				{/each}
				<div class="field-row">
					<h3 class="sub-head">{m.filter_rule_add_heading()}</h3>
					<div class="rule-form">
						<Segmented
							options={actionOptions}
							bind:value={ruleAction}
							label={m.filter_rule_action()}
						/>
						<input
							id="rule-domain"
							class="field mono"
							aria-label={m.filter_rule_domain()}
							placeholder={m.filter_rule_domain()}
							bind:value={ruleDomain}
						/>
						<Button variant="secondary" onclick={appendGuidedRule}
							>{m.filter_rule_add_button()}</Button
						>
					</div>
					<div class="switch-row">
						<span>{m.filter_rule_subdomains()}</span>
						<Switch bind:checked={ruleSubs} aria-label={m.filter_rule_subdomains()} />
					</div>
				</div>
				<div class="field-row">
					<button
						type="button"
						class="text-action"
						aria-expanded={showRaw}
						onclick={() => (showRaw = !showRaw)}
					>
						{showRaw ? m.filter_rule_hide_raw() : m.filter_rule_show_raw()}
					</button>
					{#if showRaw}
						<label class="field-label" for="fs-raw">{m.filter_rule_raw()}</label>
						<textarea id="fs-raw" class="field area mono" bind:value={formRaw} rows="6"></textarea>
					{/if}
				</div>
			</GroupedList>

			{#if editing}
				<GroupedList header={m.filter_sets_section_services()}>
					{#if editing.services.length > 0}
						<div class="field-row">
							<p class="services-line">
								{m.filter_sets_services_enabled({ services: servicesLine(editing.services) })}
							</p>
						</div>
					{/if}
					<GroupedRow
						label={m.filter_sets_manage_services()}
						detail={plural(editing.services.length, SERVICES)}
						href="/blocked-services"
					/>
				</GroupedList>
			{/if}

			{#snippet footer()}
				{#if failure}
					<div class="footer-error">
						<ErrorNotice code={failure.code} params={failure.params} />
					</div>
				{/if}
				{#if editing && confirmDelete}
					<p class="confirm-text">{m.filter_sets_delete_question()}</p>
					<div class="actions">
						<Button variant="secondary" onclick={() => (confirmDelete = false)}>
							{m.action_cancel()}
						</Button>
						<Button
							variant="danger"
							disabled={busy}
							onclick={() => void removeSet(editing?.id ?? '')}
						>
							{m.action_delete()}
						</Button>
					</div>
				{:else}
					{#if editing}
						<button type="button" class="danger-text" onclick={() => (confirmDelete = true)}>
							{m.filter_sets_delete()}
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
	.filter-sets {
		container: fsets / inline-size;
		max-width: 60rem;
	}

	.page-head {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-4);
		margin-bottom: var(--space-4);
	}
	.lead {
		max-width: 40rem;
		margin: 0;
		color: var(--label-2);
	}
	.lead a {
		color: var(--accent);
	}
	.state {
		color: var(--label-2);
	}
	.empty {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-3);
		padding: var(--space-5);
		background: var(--surface);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
	}
	.empty p {
		margin: 0;
		color: var(--label-2);
	}

	.sets {
		display: grid;
		grid-template-columns: minmax(0, 1fr);
		gap: var(--space-3);
		margin: 0;
		padding: 0;
		list-style: none;
	}
	.set-card {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		box-sizing: border-box;
		width: 100%;
		min-width: 0;
		height: 100%;
		padding: var(--space-3) var(--space-4);
		border: 1px solid var(--separator);
		border-radius: var(--r-card);
		background: var(--surface);
		box-shadow: var(--shadow);
		color: var(--label);
		font: inherit;
		text-align: start;
	}
	button.set-card {
		cursor: pointer;
	}
	button.set-card:hover {
		background: var(--surface-2);
	}
	.card-main {
		display: flex;
		flex: 1 1 auto;
		flex-direction: column;
		gap: 0.125rem;
		min-width: 0;
	}
	.card-name {
		font-size: 1rem;
		font-weight: 600;
		overflow-wrap: anywhere;
	}
	.card-detail,
	.card-lists {
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.card-tag {
		align-self: flex-start;
		padding: 0 0.375rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font-size: 0.75rem;
		color: var(--label-2);
		white-space: nowrap;
	}
	.chev {
		display: inline-flex;
		flex: 0 0 auto;
		color: var(--label-3);
	}

	@container fsets (min-width: 56rem) {
		.sets {
			grid-template-columns: repeat(2, minmax(0, 1fr));
		}
	}

	.error-text {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--danger);
	}
	.field-row {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		min-width: 0;
		padding: var(--space-3) var(--space-4);
	}
	.field-label {
		font-size: 0.8125rem;
		color: var(--label-2);
	}
	.sub-head {
		margin: var(--space-2) 0 0;
		font-size: 0.9375rem;
		font-weight: 600;
	}
	.field {
		box-sizing: border-box;
		width: 100%;
		min-height: var(--control-h);
		padding: 0.5rem 0.75rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		background: var(--surface);
		color: var(--label);
		font: inherit;
	}
	.mono {
		font-family: var(--font-mono);
	}
	.area {
		min-height: 6rem;
	}
	.rule-kind {
		display: inline-flex;
		align-items: center;
		gap: 0.25rem;
		font-size: 0.75rem;
		font-weight: 500;
		white-space: nowrap;
	}
	.rule-kind.allow {
		color: var(--ok);
	}
	.rule-kind.block {
		color: var(--danger);
	}
	.rule-form {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: var(--space-2);
	}
	.rule-form .field {
		flex: 1 1 10rem;
		width: auto;
		min-width: 0;
	}
	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		min-height: var(--control-h);
		font-size: 0.875rem;
		color: var(--label-2);
	}
	.services-line {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--label-2);
		overflow-wrap: anywhere;
	}
	.text-action,
	.danger-text {
		align-self: flex-start;
		min-height: var(--control-h);
		padding: 0 0.25rem;
		border: none;
		background: transparent;
		font: inherit;
		font-weight: 500;
		cursor: pointer;
	}
	.text-action {
		color: var(--accent);
	}
	.danger-text {
		color: var(--danger);
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
