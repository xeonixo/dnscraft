<script lang="ts">
	import { onMount } from 'svelte';
	import { resolve } from '$app/paths';
	import ErrorNotice from '$lib/components/ErrorNotice.svelte';
	import GroupedList from '$lib/components/GroupedList.svelte';
	import GroupedRow from '$lib/components/GroupedRow.svelte';
	import Switch from '$lib/components/Switch.svelte';
	import { getConfig, saveConfig } from '$lib/api/config';
	import { failureOf } from '$lib/api/result';
	import { auth } from '$lib/auth/state.svelte';
	import { m } from '$lib/paraglide/messages';

	interface McpSection {
		enabled: boolean;
		write_tools_enabled: boolean;
		max_custom_rules_per_set?: number;
	}

	const isAdmin = $derived(auth.role === 'admin');

	let available = $state(false);
	let version = $state<number | null>(null);
	let fullConfig = $state<Record<string, unknown> | null>(null);
	let mcp = $state<McpSection>({ enabled: false, write_tools_enabled: false });
	let busy = $state(false);
	let failure = $state<{ code: string; params: Record<string, unknown> } | null>(null);

	async function load(): Promise<void> {
		try {
			const snapshot = await getConfig();
			version = snapshot.version;
			fullConfig = snapshot.config;
			const section = snapshot.config?.mcp as McpSection | undefined;
			if (section && typeof section === 'object') {
				available = true;
				mcp = {
					enabled: section.enabled === true,
					write_tools_enabled: section.write_tools_enabled === true,
					max_custom_rules_per_set:
						typeof section.max_custom_rules_per_set === 'number'
							? section.max_custom_rules_per_set
							: undefined,
				};
			} else {
				available = false;
			}
		} catch {
			available = false;
		}
	}

	async function save(): Promise<void> {
		if (!isAdmin || !fullConfig) return;
		busy = true;
		failure = null;
		const next = { ...fullConfig, mcp: { ...mcp } };
		try {
			const result = await saveConfig(next, version);
			version = result.version;
			fullConfig = next;
		} catch (cause) {
			failure = failureOf(cause);
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		void load();
	});
</script>

<p class="lead">{m.settings_mcp_lead()}</p>

{#if !available}
	<GroupedList>
		<GroupedRow
			label={m.settings_mcp_unavailable_title()}
			detail={m.settings_mcp_unavailable_body()}
		/>
	</GroupedList>
{:else}
	{#if failure}
		<div class="notice">
			<ErrorNotice code={failure.code} params={failure.params} />
		</div>
	{/if}

	<GroupedList header={m.settings_mcp_group()}>
		<GroupedRow label={m.settings_mcp_enabled()}>
			{#snippet trailing()}
				<Switch
					bind:checked={mcp.enabled}
					disabled={!isAdmin}
					aria-label={m.settings_mcp_enabled()}
				/>
			{/snippet}
		</GroupedRow>
		<GroupedRow label={m.settings_mcp_write_tools()}>
			{#snippet trailing()}
				<Switch
					bind:checked={mcp.write_tools_enabled}
					disabled={!isAdmin || !mcp.enabled}
					aria-label={m.settings_mcp_write_tools()}
				/>
			{/snippet}
		</GroupedRow>
		{#if mcp.max_custom_rules_per_set !== undefined}
			<GroupedRow
				label={m.settings_mcp_rule_cap()}
				detail={String(mcp.max_custom_rules_per_set)}
				detailMono
			/>
		{/if}
	</GroupedList>

	{#if isAdmin}
		<button class="save" type="button" disabled={busy} onclick={() => void save()}
			>{m.action_save()}</button
		>
	{/if}

	<p class="rules-link"><a href={resolve('/rules')}>{m.settings_mcp_rules_link()}</a></p>

	<p class="footnote">{m.settings_mcp_footnote()}</p>
{/if}

<style>
	.lead {
		margin: 0 0 1rem;
		color: var(--label-2);
	}

	.notice {
		margin-bottom: 0.75rem;
	}

	.save {
		min-height: 2.75rem;
		margin-top: 0.75rem;
		padding: 0 1rem;
		border: 1px solid var(--separator);
		border-radius: var(--r-control);
		background: var(--surface);
		color: var(--label);
		font: inherit;
		cursor: pointer;
	}

	.rules-link {
		margin: 0.75rem 0 0;
		font-size: 0.875rem;
	}

	.rules-link a {
		color: var(--accent);
	}

	.footnote {
		margin: 1rem 0 0;
		color: var(--label-2);
		font-size: 0.84375rem;
	}
</style>
