<script lang="ts">
	import Icon from '$lib/components/Icon.svelte';
	import Value from './Value.svelte';
	import { activeGroups, type Draft, type FilterKey } from './filters';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		draft: Draft;
		/** Clears the given filter keys (one tag) and returns to the first page. */
		onremove: (keys: FilterKey[]) => void;
		onclear: () => void;
	}

	let { draft, onremove, onclear }: Props = $props();

	/** One tag per active filter group: its translated name, and the value when it has one. */
	const tags = $derived(
		activeGroups(draft).map((group) => {
			const label = labelOf(group.id);
			const value = valueOf(group.id);
			return { id: group.id, keys: group.keys, label, value };
		}),
	);

	function labelOf(id: string): string {
		switch (id) {
			case 'period':
				return m.querylog_range_label();
			case 'domain':
				return m.querylog_domain_exact();
			case 'domain_substr':
				return m.querylog_domain_contains();
			case 'client_id':
				return m.querylog_client_id();
			case 'client_name_substr':
				return m.querylog_client_name();
			case 'node_id':
				return m.querylog_node_id();
			case 'view_id':
				return m.querylog_view_id();
			case 'profile_id':
				return m.querylog_profile_id();
			case 'protocol':
				return m.querylog_protocol();
			case 'status':
				return m.querylog_status();
			case 'only_blocked':
				return m.querylog_only_blocked();
			default:
				return m.querylog_only_with_clients();
		}
	}

	/** The shown value: a preset name, a custom range, or the typed text. Booleans have none. */
	function valueOf(id: string): string | null {
		switch (id) {
			case 'period':
				if (draft.period === 'custom') {
					return `${draft.from === '' ? '…' : draft.from} – ${draft.to === '' ? '…' : draft.to}`;
				}
				return draft.period === '' ? null : draft.period;
			case 'domain':
				return draft.domain;
			case 'domain_substr':
				return draft.domain_substr;
			case 'client_id':
				return draft.client_id;
			case 'client_name_substr':
				return draft.client_name_substr;
			case 'node_id':
				return draft.node_id;
			case 'view_id':
				return draft.view_id;
			case 'profile_id':
				return draft.profile_id;
			case 'protocol':
				return draft.protocol;
			case 'status':
				return draft.status;
			default:
				return null;
		}
	}
</script>

{#if tags.length > 0}
	<div class="tags">
		<ul class="list" aria-label={m.querylog_active_label()}>
			{#each tags as tag (tag.id)}
				<li class="tag">
					<span class="text">
						{tag.label}{#if tag.value !== null}: <Value value={tag.value} mono />{/if}
					</span>
					<button
						type="button"
						class="remove"
						aria-label={m.querylog_tag_remove({ filter: tag.label })}
						onclick={() => onremove(tag.keys)}
					>
						<Icon name="x" size="1rem" strokeWidth={1.8} />
					</button>
				</li>
			{/each}
		</ul>
		<button type="button" class="reset" onclick={onclear}>{m.querylog_filter_reset()}</button>
	</div>
{/if}

<style>
	.tags {
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		gap: 0.5rem;
	}

	.list {
		display: flex;
		flex-wrap: wrap;
		gap: 0.5rem;
		margin: 0;
		padding: 0;
		list-style: none;
	}

	/* Rectilinear chips: the prototype's tags use the control radius, not a pill. */
	.tag {
		display: inline-flex;
		align-items: center;
		max-width: 100%;
		min-height: 2.75rem;
		padding: 0 0 0 0.625rem;
		background: var(--surface-2);
		border: 1px solid var(--separator);
		border-radius: var(--r-ctl);
		font-size: 0.8125rem;
		color: var(--label);
	}

	.text {
		min-width: 0;
		overflow-wrap: anywhere;
	}

	.remove,
	.reset {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		min-width: 2.75rem;
		min-height: 2.75rem;
		padding: 0;
		background: transparent;
		border: 0;
		color: var(--label-2);
		font: inherit;
		cursor: pointer;
	}

	.reset {
		padding: 0 0.5rem;
		color: var(--accent);
		font-size: 0.875rem;
	}

	.remove:hover,
	.reset:hover {
		color: var(--label);
		text-decoration: underline;
	}
</style>
