<script lang="ts">
	import ErrorNotice from './ErrorNotice.svelte';
	import Icon from './Icon.svelte';
	import GroupedList from './GroupedList.svelte';
	import { errorMessage } from '$lib/i18n/locale';
	import { m } from '$lib/paraglide/messages';
	import type { Result } from '$lib/api/result';
	import { NOT_READY_CODE } from '$lib/api/result';

	interface Props {
		/** The read this block stands for. Renders nothing once it is `ok`. */
		result: Result<unknown>;
		onretry?: () => void;
	}

	let { result, onretry }: Props = $props();
</script>

{#if result.kind === 'loading'}
	<GroupedList>
		<p class="state">{m.state_loading()}</p>
	</GroupedList>
{:else if result.kind === 'unavailable'}
	<GroupedList>
		<div class="state unavailable">
			<span class="symbol"><Icon name="ban" size="1.5rem" strokeWidth={1.5} /></span>
			{#if result.code === NOT_READY_CODE}
				<p>{errorMessage(result.code)}</p>
			{:else}
				<p class="title">{m.dashboard_unavailable_title()}</p>
				<p class="detail">{m.dashboard_unavailable_body()}</p>
			{/if}
		</div>
	</GroupedList>
{:else if result.kind === 'error'}
	<ErrorNotice code={result.code} params={result.params} {onretry} />
{/if}

<style>
	.state {
		margin: 0;
		padding: 1rem;
		color: var(--label-2);
	}

	.unavailable {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: 0.375rem;
	}

	.symbol {
		display: inline-flex;
		color: var(--label-3);
	}

	.title {
		margin: 0;
		font-weight: 600;
		color: var(--label);
	}

	.detail,
	.unavailable p {
		margin: 0;
	}
</style>
