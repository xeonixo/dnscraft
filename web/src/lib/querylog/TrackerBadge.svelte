<script lang="ts">
	import type { TrackerLabel } from '$lib/api/query-log';
	import { displayText, neutralize } from '$lib/safe-text';
	import { trackerCategoryLabel } from './view';

	interface Props {
		tracker: TrackerLabel;
	}

	let { tracker }: Props = $props();
	const category = $derived(trackerCategoryLabel(tracker.category));
</script>

<!-- Name comes from a downloaded database: text only, length-capped. -->
<span class="tracker" title={neutralize(`${tracker.name} · ${category}`)}>
	<span class="name">{displayText(tracker.name, 32).text}</span>
	<span class="category">{category}</span>
</span>

<style>
	.tracker {
		display: inline-flex;
		flex-wrap: wrap;
		gap: 0 0.375rem;
		align-items: baseline;
		max-inline-size: 100%;
		padding: 0 0.375rem;
		border-radius: var(--r-ctl);
		background: var(--surface);
		box-shadow: inset 0 0 0 1px var(--separator);
		font-size: 0.75rem;
		color: var(--label-2);
	}

	.name {
		font-weight: 600;
		color: var(--label);
	}
</style>
