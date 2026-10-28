<script lang="ts">
	import { tick, type Snippet } from 'svelte';
	import { m } from '$lib/paraglide/messages';

	interface Props {
		open: boolean;
		title: string;
		onclose: () => void;
		children: Snippet;
		/** Wide screens (55rem and up): a centred dialog of at most 32rem instead of a bottom sheet. */
		centeredOnWide?: boolean;
		/** Optional action bar pinned under the scrolling body (header stays on top). */
		footer?: Snippet;
	}

	let { open, title, onclose, children, centeredOnWide = false, footer }: Props = $props();
	const titleId = $props.id();
	let dialog: HTMLDivElement | undefined = $state();

	const FOCUSABLE =
		'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

	function focusables(root: HTMLElement): HTMLElement[] {
		return [...root.querySelectorAll<HTMLElement>(FOCUSABLE)];
	}

	// Opening moves focus into the dialog; closing (or unmounting) returns it to the trigger.
	$effect(() => {
		if (!open) return;
		const trigger = document.activeElement;
		let active = true;
		void tick().then(() => {
			if (!active || !dialog) return;
			(focusables(dialog)[0] ?? dialog).focus();
		});
		return () => {
			active = false;
			if (trigger instanceof HTMLElement) trigger.focus();
		};
	});

	// Escape closes; Tab and Shift+Tab wrap inside the dialog so focus cannot leave it.
	function onkeydown(event: KeyboardEvent): void {
		if (event.key === 'Escape') {
			event.preventDefault();
			event.stopPropagation();
			onclose();
			return;
		}
		if (event.key !== 'Tab' || !dialog) return;

		const items = focusables(dialog);
		const first = items[0];
		const last = items[items.length - 1];
		const current = document.activeElement;
		const inside = current instanceof Node && dialog.contains(current);

		if (!first || !last) {
			event.preventDefault();
		} else if (event.shiftKey && (!inside || current === first || current === dialog)) {
			event.preventDefault();
			last.focus();
		} else if (!event.shiftKey && (!inside || current === last)) {
			event.preventDefault();
			first.focus();
		}
	}
</script>

{#if open}
	<button
		type="button"
		class="sheet-scrim"
		tabindex="-1"
		aria-label={m.action_cancel()}
		onclick={onclose}
	></button>
	<div class="sheet-layer" class:centered-on-wide={centeredOnWide}>
		<div
			class="sheet"
			class:has-footer={footer !== undefined}
			role="dialog"
			aria-modal="true"
			aria-labelledby={titleId}
			tabindex="-1"
			bind:this={dialog}
			{onkeydown}
		>
			<span class="grab" aria-hidden="true"></span>
			<h2 id={titleId}>{title}</h2>
			{#if footer}
				<div class="sheet-body">
					{@render children()}
				</div>
				<div class="sheet-footer">
					{@render footer()}
				</div>
			{:else}
				{@render children()}
			{/if}
		</div>
	</div>
{/if}

<style>
	.sheet-scrim {
		position: fixed;
		inset: 0;
		z-index: 60;
		padding: 0;
		border: 0;
		background: var(--scrim);
		cursor: default;
	}

	.sheet-layer {
		position: fixed;
		inset: 0;
		z-index: 61;
		display: grid;
		place-items: end center;
		pointer-events: none;
	}

	.sheet {
		width: 100%;
		max-width: 32.5rem;
		max-height: 90dvh;
		overflow-y: auto;
		padding: 1rem 1.25rem 1.5rem;
		background: var(--surface);
		border-radius: 0.875rem 0.875rem 0 0;
		box-shadow: var(--shadow-sheet);
		pointer-events: auto;
	}

	.sheet:focus {
		outline: none;
	}

	/* With a footer the header stays fixed, the body scrolls and the action bar stays pinned. */
	.sheet.has-footer {
		display: flex;
		flex-direction: column;
		padding: 1rem 1.25rem 0;
		overflow: hidden;
	}

	.sheet-body {
		flex: 1 1 auto;
		min-height: 0;
		margin: 0 -1.25rem;
		padding: 0 1.25rem var(--space-4);
		overflow-y: auto;
		overscroll-behavior: contain;
	}

	.sheet-footer {
		flex: 0 0 auto;
		display: flex;
		flex-wrap: wrap;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-2) var(--space-3);
		margin: 0 -1.25rem;
		padding: var(--space-3) 1.25rem max(var(--space-3), env(safe-area-inset-bottom));
		border-top: 1px solid var(--separator);
		background: var(--surface);
	}

	@media (min-width: 55rem) {
		.sheet-layer.centered-on-wide {
			place-items: center;
		}

		.sheet-layer.centered-on-wide .sheet {
			max-width: 32rem;
			border-radius: var(--r-card);
		}

		.sheet-layer.centered-on-wide .grab {
			display: none;
		}
	}

	.grab {
		display: block;
		width: 2.25rem;
		height: 0.3125rem;
		margin: 0 auto 0.875rem;
		border-radius: 0.1875rem;
		background: var(--label-3);
	}

	h2 {
		margin: 0 0 0.875rem;
		font-size: 1.0625rem;
		font-weight: 600;
		letter-spacing: -0.01em;
	}
</style>
