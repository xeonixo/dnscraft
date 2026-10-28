<script lang="ts">
	import Button from '$lib/components/Button.svelte';
	import Segmented from '$lib/components/Segmented.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { errorMessage } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';
	import {
		DEFAULT_LIMIT,
		PAGE_SIZES,
		PROTOCOLS,
		emptyDraft,
		localToRfc3339,
		rfc3339ToLocal,
		validateDraft,
		type Draft,
		type FieldErrors,
		type FilterKey,
	} from './filters';

	interface Props {
		/** The filters the URL currently holds. A change of this value replaces the draft. */
		initial: Draft;
		/** Errors that came from the URL or the server, shown until the form is applied again. */
		external: FieldErrors;
		onapply: (draft: Draft) => void;
		onreset: () => void;
	}

	let { initial, external, onapply, onreset }: Props = $props();

	const uid = $props.id();
	const inputId = (key: FilterKey): string => `${uid}-${key}`;
	const errorId = (key: FilterKey): string => `${uid}-${key}-error`;

	let draft = $state<Draft>(emptyDraft());
	let submitted = $state(false);
	let syncedKey: string | null = null;

	// Replaces the draft when the URL-side filters change (navigation, tags, search box, reset).
	$effect(() => {
		const key = new URLSearchParams(
			Object.entries(initial).filter(([, value]) => value !== ''),
		).toString();
		if (key === syncedKey) return;
		syncedKey = key;
		draft = { ...initial };
		submitted = false;
	});

	const fieldErrors = $derived<FieldErrors>(submitted ? validateDraft(draft) : external);

	const sizeOptions = $derived<string[]>(
		(PAGE_SIZES as readonly string[]).includes(draft.limit) || draft.limit === ''
			? [...PAGE_SIZES]
			: [...PAGE_SIZES, draft.limit],
	);
	const orderOptions = $derived<{ value: string; label: string }[]>([
		{ value: 'asc', label: m.querylog_order_asc() },
		{ value: 'desc', label: m.querylog_order_desc() },
	]);

	function apply(): void {
		submitted = true;
		if (Object.keys(validateDraft(draft)).length === 0) onapply({ ...draft });
	}

	function reset(): void {
		draft = emptyDraft();
		submitted = false;
		onreset();
	}

	/** Text for a field's error, or null when the field is valid. */
	function errorOf(key: FilterKey): string | null {
		const code = fieldErrors[key];
		return code === undefined ? null : errorMessage(code);
	}
</script>

{#snippet fieldError(key: FilterKey)}
	{@const text = errorOf(key)}
	{#if text !== null}
		<p class="error" id={errorId(key)}>{text}</p>
	{/if}
{/snippet}

<form
	class="filters"
	onsubmit={(event) => {
		event.preventDefault();
		apply();
	}}
>
	{#if draft.period === 'custom'}
		<section class="group" aria-labelledby={`${uid}-time`}>
			<h3 id={`${uid}-time`}>{m.querylog_section_time()}</h3>
			<div class="grid">
				<div class="field-wrap">
					<label class="field-label" for={inputId('from')}>{m.querylog_from()}</label>
					<input
						id={inputId('from')}
						class="field"
						type="datetime-local"
						value={rfc3339ToLocal(draft.from)}
						aria-invalid={errorOf('from') !== null}
						aria-describedby={errorOf('from') !== null ? errorId('from') : undefined}
						oninput={(event) => (draft.from = localToRfc3339(event.currentTarget.value))}
					/>
					{@render fieldError('from')}
				</div>
				<div class="field-wrap">
					<label class="field-label" for={inputId('to')}>{m.querylog_to()}</label>
					<input
						id={inputId('to')}
						class="field"
						type="datetime-local"
						value={rfc3339ToLocal(draft.to)}
						aria-invalid={errorOf('to') !== null}
						aria-describedby={errorOf('to') !== null ? errorId('to') : undefined}
						oninput={(event) => (draft.to = localToRfc3339(event.currentTarget.value))}
					/>
					{@render fieldError('to')}
				</div>
			</div>
		</section>
	{/if}

	<section class="group" aria-labelledby={`${uid}-domain-group`}>
		<h3 id={`${uid}-domain-group`}>{m.querylog_section_domain()}</h3>
		<div class="grid">
			<div class="field-wrap">
				<label class="field-label" for={inputId('domain')}>{m.querylog_domain_exact()}</label>
				<input
					id={inputId('domain')}
					class="field mono-field"
					type="text"
					maxlength="253"
					autocomplete="off"
					autocapitalize="none"
					spellcheck="false"
					bind:value={draft.domain}
					aria-invalid={errorOf('domain') !== null}
					aria-describedby={errorOf('domain') !== null ? errorId('domain') : undefined}
				/>
				{@render fieldError('domain')}
			</div>
			<div class="field-wrap">
				<label class="field-label" for={inputId('domain_substr')}
					>{m.querylog_domain_contains()}</label
				>
				<input
					id={inputId('domain_substr')}
					class="field mono-field"
					type="text"
					maxlength="253"
					autocomplete="off"
					autocapitalize="none"
					spellcheck="false"
					bind:value={draft.domain_substr}
					aria-invalid={errorOf('domain_substr') !== null}
					aria-describedby={errorOf('domain_substr') !== null
						? errorId('domain_substr')
						: undefined}
				/>
				{@render fieldError('domain_substr')}
			</div>
		</div>
	</section>

	<section class="group" aria-labelledby={`${uid}-device-group`}>
		<h3 id={`${uid}-device-group`}>{m.querylog_section_device()}</h3>
		<div class="grid">
			<div class="field-wrap">
				<label class="field-label" for={inputId('client_id')}>{m.querylog_client_id()}</label>
				<input
					id={inputId('client_id')}
					class="field mono-field"
					type="text"
					maxlength="128"
					autocomplete="off"
					spellcheck="false"
					bind:value={draft.client_id}
					aria-invalid={errorOf('client_id') !== null}
					aria-describedby={errorOf('client_id') !== null ? errorId('client_id') : undefined}
				/>
				{@render fieldError('client_id')}
			</div>
			<div class="field-wrap">
				<label class="field-label" for={inputId('client_name_substr')}
					>{m.querylog_client_name()}</label
				>
				<input
					id={inputId('client_name_substr')}
					class="field"
					type="text"
					maxlength="128"
					autocomplete="off"
					bind:value={draft.client_name_substr}
					aria-invalid={errorOf('client_name_substr') !== null}
					aria-describedby={errorOf('client_name_substr') !== null
						? errorId('client_name_substr')
						: undefined}
				/>
				{@render fieldError('client_name_substr')}
			</div>
			<div class="field-wrap">
				<label class="field-label" for={inputId('node_id')}>{m.querylog_node_id()}</label>
				<input
					id={inputId('node_id')}
					class="field mono-field"
					type="text"
					maxlength="128"
					autocomplete="off"
					spellcheck="false"
					bind:value={draft.node_id}
					aria-invalid={errorOf('node_id') !== null}
					aria-describedby={errorOf('node_id') !== null ? errorId('node_id') : undefined}
				/>
				{@render fieldError('node_id')}
			</div>
			<div class="field-wrap">
				<label class="field-label" for={inputId('view_id')}>{m.querylog_view_id()}</label>
				<input
					id={inputId('view_id')}
					class="field mono-field"
					type="text"
					maxlength="128"
					autocomplete="off"
					spellcheck="false"
					bind:value={draft.view_id}
					aria-invalid={errorOf('view_id') !== null}
					aria-describedby={errorOf('view_id') !== null ? errorId('view_id') : undefined}
				/>
				{@render fieldError('view_id')}
			</div>
			<div class="field-wrap">
				<label class="field-label" for={inputId('profile_id')}>{m.querylog_profile_id()}</label>
				<input
					id={inputId('profile_id')}
					class="field mono-field"
					type="text"
					maxlength="128"
					autocomplete="off"
					spellcheck="false"
					bind:value={draft.profile_id}
					aria-invalid={errorOf('profile_id') !== null}
					aria-describedby={errorOf('profile_id') !== null ? errorId('profile_id') : undefined}
				/>
				{@render fieldError('profile_id')}
			</div>
		</div>
	</section>

	<section class="group" aria-labelledby={`${uid}-answer-group`}>
		<h3 id={`${uid}-answer-group`}>{m.querylog_section_answer()}</h3>
		<div class="grid">
			<div class="field-wrap">
				<label class="field-label" for={inputId('protocol')}>{m.querylog_protocol()}</label>
				<select
					id={inputId('protocol')}
					class="field"
					value={draft.protocol}
					aria-invalid={errorOf('protocol') !== null}
					aria-describedby={errorOf('protocol') !== null ? errorId('protocol') : undefined}
					onchange={(event) => (draft.protocol = event.currentTarget.value)}
				>
					<option value="">{m.querylog_all()}</option>
					{#each PROTOCOLS as protocol (protocol)}
						<option value={protocol}>{protocol}</option>
					{/each}
				</select>
				{@render fieldError('protocol')}
			</div>
			<div class="field-wrap">
				<label class="field-label" for={inputId('status')}>{m.querylog_status()}</label>
				<select
					id={inputId('status')}
					class="field"
					value={draft.status}
					aria-invalid={errorOf('status') !== null}
					aria-describedby={errorOf('status') !== null ? errorId('status') : undefined}
					onchange={(event) => (draft.status = event.currentTarget.value)}
				>
					<option value="">{m.querylog_all()}</option>
					<option value="allowed">{m.querylog_status_allowed()}</option>
					<option value="blocked">{m.querylog_status_blocked()}</option>
					<option value="dnssec_bogus">{m.querylog_status_dnssec_bogus()}</option>
					<option value="servfail">{m.querylog_status_servfail()}</option>
				</select>
				{@render fieldError('status')}
			</div>
		</div>
		<div class="switch-row">
			<span id={`${uid}-only-blocked`}>{m.querylog_only_blocked()}</span>
			<Switch
				checked={draft.only_blocked === 'true'}
				aria-labelledby={`${uid}-only-blocked`}
				onchange={(event) => (draft.only_blocked = event.currentTarget.checked ? 'true' : '')}
			/>
		</div>
		<div class="switch-row">
			<span id={`${uid}-only-clients`}>{m.querylog_only_with_clients()}</span>
			<Switch
				checked={draft.only_with_clients === 'true'}
				aria-labelledby={`${uid}-only-clients`}
				onchange={(event) => (draft.only_with_clients = event.currentTarget.checked ? 'true' : '')}
			/>
		</div>
		{@render fieldError('only_blocked')}
		{@render fieldError('only_with_clients')}
	</section>

	<section class="group" aria-labelledby={`${uid}-order-group`}>
		<h3 id={`${uid}-order-group`}>{m.querylog_section_order()}</h3>
		<div class="grid">
			<div class="field-wrap">
				<label class="field-label" for={inputId('order_by')}>{m.querylog_order_by()}</label>
				<select
					id={inputId('order_by')}
					class="field"
					value={draft.order_by || 'time'}
					aria-invalid={errorOf('order_by') !== null}
					aria-describedby={errorOf('order_by') !== null ? errorId('order_by') : undefined}
					onchange={(event) => (draft.order_by = event.currentTarget.value)}
				>
					<option value="time">{m.querylog_order_time()}</option>
					<option value="client">{m.querylog_order_client()}</option>
					<option value="domain">{m.querylog_order_domain()}</option>
					<option value="rcode">{m.querylog_order_rcode()}</option>
				</select>
				{@render fieldError('order_by')}
			</div>
			<div class="field-wrap">
				<span class="field-label">{m.querylog_order_dir()}</span>
				<Segmented
					options={orderOptions}
					value={draft.order || 'desc'}
					label={m.querylog_order_dir()}
					onchange={(value) => (draft.order = value)}
				/>
				{@render fieldError('order')}
			</div>
			<div class="field-wrap">
				<label class="field-label" for={inputId('limit')}>{m.querylog_limit()}</label>
				<select
					id={inputId('limit')}
					class="field"
					value={draft.limit || DEFAULT_LIMIT}
					aria-invalid={errorOf('limit') !== null}
					aria-describedby={errorOf('limit') !== null ? errorId('limit') : undefined}
					onchange={(event) => (draft.limit = event.currentTarget.value)}
				>
					{#each sizeOptions as size (size)}
						<option value={size}>{size}</option>
					{/each}
				</select>
				{@render fieldError('limit')}
			</div>
		</div>
	</section>

	<div class="actions">
		<Button onclick={reset}>{m.querylog_filter_reset()}</Button>
		<Button variant="primary" type="submit">{m.querylog_filter_apply()}</Button>
	</div>
</form>

<style>
	.filters {
		display: flex;
		flex-direction: column;
		gap: 1rem;
		min-width: 0;
	}

	.group {
		display: flex;
		flex-direction: column;
		gap: 0.625rem;
		min-width: 0;
	}

	h3 {
		margin: 0;
		font-size: 0.8125rem;
		font-weight: 500;
		color: var(--label-2);
	}

	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(12.5rem, 1fr));
		gap: 0.75rem;
	}

	.field-wrap {
		display: flex;
		flex-direction: column;
		gap: 0.25rem;
		min-width: 0;
	}

	.field-label {
		font-size: 0.8125rem;
		color: var(--label-2);
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
		font-size: 0.9375rem;
	}

	.mono-field {
		font-family: var(--font-mono);
		font-size: 0.875rem;
	}

	[aria-invalid='true'] {
		border-color: var(--danger);
	}

	.error {
		margin: 0;
		font-size: 0.8125rem;
		color: var(--danger);
	}

	.switch-row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 0.75rem;
		min-height: 2.75rem;
		font-size: 0.9375rem;
	}

	.actions {
		display: flex;
		flex-wrap: wrap;
		justify-content: flex-end;
		gap: 0.625rem;
	}
</style>
