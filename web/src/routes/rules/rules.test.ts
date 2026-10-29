// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import RulesPage from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });

type Handler = (init?: RequestInit, url?: string) => Response;

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

const SET_DEFAULT_RULES =
	'! Schule\n||ads.example^\n|exact.example^\n@@||api.github.com^\n||ads.example.net^$important';

function minutesFromNow(minutes: number): string {
	return new Date(Date.now() + minutes * 60_000).toISOString();
}

function defaultHandlers(): Record<string, Handler> {
	return {
		'GET /api/v1/filter-sets': () =>
			ok({
				filter_sets: [
					{
						id: 'default',
						name: 'Standard',
						lists: [],
						custom_rules: SET_DEFAULT_RULES,
						services: [],
						block_mode: 'refused',
					},
					{
						id: 'kids',
						name: 'Kinder',
						lists: [],
						custom_rules: '@@|lernen.example.de^',
						services: [],
						block_mode: 'nxdomain',
					},
				],
			}),
		'GET /api/v1/filtering/mcp-rules': (_init, url) => {
			const params = new URL(String(url), 'http://localhost').searchParams;
			const kind = params.get('kind') ?? 'rules';
			const setId = params.get('filter_set_id') ?? 'default';
			const page = { filter_set_id: setId, kind, has_more: false, next_offset: null };
			if (kind === 'temporary_allows') {
				return ok({
					...page,
					temporary_allows:
						setId === 'default'
							? [
									{
										domain: 'allowed.example.test',
										include_subdomains: false,
										created_at: minutesFromNow(-1),
										expires_at: minutesFromNow(4),
										filter_set_id: 'default',
									},
								]
							: [],
				});
			}
			if (kind === 'pauses') {
				return ok({
					...page,
					pauses:
						setId === 'kids' ? [{ filter_set_id: 'kids', paused_until: minutesFromNow(12) }] : [],
				});
			}
			return ok({
				...page,
				rules:
					setId === 'default'
						? [
								{
									id: 'm1',
									domain: 'tracker.example',
									include_subdomains: true,
									rule_text: '||tracker.example^',
									created_at: '2026-10-26T08:00:00Z',
									expires_at: null,
									filter_set_id: 'default',
								},
								{
									id: 'm2',
									domain: 'soon.example',
									include_subdomains: false,
									rule_text: '|soon.example^',
									created_at: '2026-10-26T09:00:00Z',
									expires_at: minutesFromNow(29 * 24 * 60),
									filter_set_id: 'default',
								},
							]
						: [],
			});
		},
		'PUT /api/v1/filter-sets': () =>
			ok({
				version: 2,
				filter_set: {},
				created: false,
			}),
		'DELETE /api/v1/filtering/custom-rules': () => ok({ removed: true }),
		'POST /api/v1/filtering/resume': () => ok({ filter_set_id: 'kids', resumed: true }),
		'GET /api/v1/filtering/mcp-proposals': () => ok({ proposals: [] }),
	};
}

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = { ...defaultHandlers(), ...overrides };
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		const handler = handlers[`${init?.method ?? 'GET'} ${url.split('?')[0]}`];
		return handler ? handler(init, url) : json(404, { error: { code: 'control_api.not_found' } });
	});
}

beforeEach(() => {
	fetchMock = vi.fn();
	vi.stubGlobal('fetch', fetchMock);
	setPrincipal({ role: 'admin', actorId: 'admin', actorType: 'user', csrfToken: 'tok' });
	serve();
});

afterEach(() => {
	cleanup();
	endSession();
	vi.unstubAllGlobals();
});

const bodyOf = (method: string): Record<string, unknown> | undefined => {
	const call = fetchMock.mock.calls.find(([, init]) => init?.method === method);
	return call ? JSON.parse(String(call[1]?.body)) : undefined;
};

/** The subline of a row is one string; this composes it the way the page does. */
const subline = (...parts: string[]): string => parts.join(' · ');

/** The switch input is visually hidden; clicking its label toggles it, as a user does. */
const subdomainSwitch = (dialog: HTMLElement): HTMLElement => {
	const input = within(dialog).getByRole('switch', { name: m.rules_add_subdomains() });
	return input.closest('label') ?? input;
};

describe('Regeln page: list', () => {
	it('lists the text rules of every set and the MCP rules, skipping comment lines', async () => {
		render(RulesPage);
		expect(await screen.findByRole('button', { name: /^ads\.example / })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /exact\.example/ })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /api\.github\.com/ })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /tracker\.example/ })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: /lernen\.example\.de/ })).toBeInTheDocument();
		expect(screen.queryByText('! Schule')).toBeNull();
	});

	it('shows the set, origin and scope of a text rule, and the expiry of an MCP rule', async () => {
		render(RulesPage);
		// Two rows (ads.example and the allow of api.github.com) share this subline.
		expect(
			(
				await screen.findAllByText(
					subline(
						m.rules_set_line({ set: 'Standard' }),
						m.rules_origin_text(),
						m.rules_scope_subdomains(),
					),
				)
			).length,
		).toBeGreaterThan(0);
		expect(
			screen.getByText(
				subline(
					m.rules_set_line({ set: 'Standard' }),
					m.rules_origin_mcp(),
					m.rules_expiry_none(),
					m.rules_scope_subdomains(),
				),
			),
		).toBeInTheDocument();
	});

	it('shows an advanced line as a labelled row with its raw text', async () => {
		render(RulesPage);
		expect(await screen.findByText(m.rules_advanced())).toBeInTheDocument();
		expect(screen.getByText('||ads.example.net^$important')).toBeInTheDocument();
	});

	it('shows active temporary allows and pauses with their remaining minutes', async () => {
		render(RulesPage);
		expect(await screen.findByText(m.rules_active_heading())).toBeInTheDocument();
		expect(
			screen.getByText(
				subline(
					m.rules_origin_temp(),
					m.rules_set_line({ set: 'Standard' }),
					m.rules_remaining({ minutes: 4 }),
					m.rules_scope_exact(),
				),
			),
		).toBeInTheDocument();
		expect(
			screen.getByText(subline(m.rules_paused(), m.rules_remaining({ minutes: 12 }))),
		).toBeInTheDocument();
	});

	it('resumes a paused filter set from the active section', async () => {
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByRole('button', { name: m.rules_resume() }));
		await waitFor(() => expect(bodyOf('POST')).toEqual({ filter_set_id: 'kids' }));
	});

	it('filters by search text, by action and by filter set', async () => {
		const user = userEvent.setup();
		render(RulesPage);
		await screen.findByRole('button', { name: /tracker\.example/ });

		await user.type(screen.getByRole('searchbox', { name: m.rules_search_label() }), 'EXAMPLE.NET');
		expect(screen.queryByRole('button', { name: /tracker\.example/ })).toBeNull();
		expect(screen.getByRole('button', { name: /ads\.example\.net/ })).toBeInTheDocument();

		await user.clear(screen.getByRole('searchbox', { name: m.rules_search_label() }));
		const actions = screen.getByRole('radiogroup', { name: m.rules_action_label() });
		await user.click(within(actions).getByRole('radio', { name: m.rules_filter_allowed() }));
		expect(screen.queryByRole('button', { name: /^ads\.example / })).toBeNull();
		expect(screen.getByRole('button', { name: /api\.github\.com/ })).toBeInTheDocument();

		await user.click(within(actions).getByRole('radio', { name: m.rules_filter_all() }));
		await user.selectOptions(
			screen.getByRole('combobox', { name: m.rules_filter_set_label() }),
			'kids',
		);
		expect(screen.getByRole('button', { name: /lernen\.example\.de/ })).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: /tracker\.example/ })).toBeNull();
	});

	it('shows the empty state with an add button when no set has rules', async () => {
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'default',
							name: 'Standard',
							lists: [],
							custom_rules: '',
							services: [],
							block_mode: 'refused',
						},
					],
				}),
			'GET /api/v1/filtering/mcp-rules': (_init, url) =>
				ok({
					filter_set_id: 'default',
					kind: new URL(String(url), 'http://localhost').searchParams.get('kind') ?? 'rules',
					rules: [],
					temporary_allows: [],
					pauses: [],
					has_more: false,
					next_offset: null,
				}),
		});
		render(RulesPage);
		expect(await screen.findByText(m.rules_empty_body())).toBeInTheDocument();
		expect(screen.getAllByRole('button', { name: m.rules_add() })).toHaveLength(2);
	});
});

describe('Regeln page: add', () => {
	it('writes the built rule into a fresh copy of the chosen set', async () => {
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByRole('button', { name: m.rules_add() }));
		const dialog = await screen.findByRole('dialog');

		await user.type(within(dialog).getByLabelText(m.rules_add_domain()), 'new.example');
		await user.click(subdomainSwitch(dialog));
		await user.selectOptions(within(dialog).getByLabelText(m.rules_field_set()), 'kids');
		await user.click(within(dialog).getByRole('button', { name: m.rules_add() }));

		await waitFor(() =>
			expect(bodyOf('PUT')).toMatchObject({
				id: 'kids',
				custom_rules: '@@|lernen.example.de^\n||new.example^',
			}),
		);
	});

	it('says a rule that already exists and writes nothing', async () => {
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByRole('button', { name: m.rules_add() }));
		const dialog = await screen.findByRole('dialog');

		await user.type(within(dialog).getByLabelText(m.rules_add_domain()), 'ads.example');
		await user.click(subdomainSwitch(dialog));
		await user.click(within(dialog).getByRole('button', { name: m.rules_add() }));

		expect(
			await within(dialog).findByText(m.rules_add_exists({ set: 'Standard' })),
		).toBeInTheDocument();
		expect(bodyOf('PUT')).toBeUndefined();
	});

	it('refuses an empty or malformed domain without calling the API', async () => {
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByRole('button', { name: m.rules_add() }));
		const dialog = await screen.findByRole('dialog');

		await user.click(within(dialog).getByRole('button', { name: m.rules_add() }));
		expect(within(dialog).getByText(m.rules_add_domain_empty())).toBeInTheDocument();

		await user.type(within(dialog).getByLabelText(m.rules_add_domain()), 'bad/path');
		await user.click(within(dialog).getByRole('button', { name: m.rules_add() }));
		expect(within(dialog).getByText(m.rules_add_domain_invalid())).toBeInTheDocument();
		expect(bodyOf('PUT')).toBeUndefined();
	});
});

describe('Regeln page: remove', () => {
	it('removes exactly the chosen text line and keeps the other lines as they were', async () => {
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByRole('button', { name: /exact\.example/ }));
		const dialog = await screen.findByRole('dialog');

		await user.click(within(dialog).getByRole('button', { name: m.rules_remove() }));
		await user.click(within(dialog).getByRole('button', { name: m.rules_remove() }));

		await waitFor(() =>
			expect(bodyOf('PUT')).toMatchObject({
				id: 'default',
				custom_rules: '! Schule\n||ads.example^\n@@||api.github.com^\n||ads.example.net^$important',
			}),
		);
	});

	it('deletes an MCP rule through the custom-rules endpoint', async () => {
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByRole('button', { name: /tracker\.example/ }));
		const dialog = await screen.findByRole('dialog');

		await user.click(within(dialog).getByRole('button', { name: m.rules_remove() }));
		await user.click(within(dialog).getByRole('button', { name: m.rules_remove() }));

		await waitFor(() =>
			expect(bodyOf('DELETE')).toEqual({ domain: 'tracker.example', filter_set_id: 'default' }),
		);
	});
});

describe('Regeln page: viewer', () => {
	it('shows rows read-only: no add button, no sheet on click', async () => {
		setPrincipal({ role: 'viewer', actorId: 'v', actorType: 'user', csrfToken: 'tok' });
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByText('exact.example'));
		expect(screen.queryByRole('dialog')).toBeNull();
		expect(screen.queryByRole('button', { name: m.rules_add() })).toBeNull();
	});
});

describe('Regeln page: proposals', () => {
	const proposal = {
		id: 'p1',
		filter_set_id: 'default',
		domain: 'cdn.tinypass.com',
		include_subdomains: false,
		reason: 'Needed for the article page',
		rule_text: '@@|cdn.tinypass.com^',
		created_at: '2026-10-29T18:00:00Z',
		expires_at: minutesFromNow(6 * 24 * 60),
	};

	it('shows nothing when no assistant proposed anything, and survives a node without the endpoint', async () => {
		serve({ 'GET /api/v1/filtering/mcp-proposals': () => json(404, { error: { code: 'x' } }) });
		render(RulesPage);
		await screen.findByRole('button', { name: /^ads\.example / });
		expect(screen.queryByText(m.rules_proposals_heading())).toBeNull();
	});

	it('lists a proposal with its reason and confirms it as a permanent exception', async () => {
		serve({
			'GET /api/v1/filtering/mcp-proposals': () => ok({ proposals: [proposal] }),
			'POST /api/v1/filtering/mcp-proposals/p1/confirm': () =>
				ok({ decision: 'confirmed', filter_set_id: 'default', rule_text: proposal.rule_text }),
		});
		const user = userEvent.setup();
		render(RulesPage);
		expect(await screen.findByText(m.rules_proposals_heading())).toBeInTheDocument();
		expect(screen.getByText('cdn.tinypass.com')).toBeInTheDocument();
		expect(
			screen.getByText(
				/Begründung: Needed for the article page|Reason: Needed for the article page/,
			),
		).toBeInTheDocument();

		await user.click(screen.getByRole('button', { name: m.rules_proposal_allow() }));
		await waitFor(() =>
			expect(
				fetchMock.mock.calls.some(
					([url, init]) =>
						String(url).endsWith('/mcp-proposals/p1/confirm') && init?.method === 'POST',
				),
			).toBe(true),
		);
		expect(
			await screen.findByText(m.rules_proposal_done({ rule: proposal.rule_text, set: 'Standard' })),
		).toBeInTheDocument();
	});

	it('rejects a proposal without adding a rule', async () => {
		serve({
			'GET /api/v1/filtering/mcp-proposals': () => ok({ proposals: [proposal] }),
			'POST /api/v1/filtering/mcp-proposals/p1/reject': () => ok({ decision: 'rejected' }),
		});
		const user = userEvent.setup();
		render(RulesPage);
		await user.click(await screen.findByRole('button', { name: m.rules_proposal_reject() }));
		expect(await screen.findByText(m.rules_proposal_rejected())).toBeInTheDocument();
		expect(fetchMock.mock.calls.some(([, init]) => init?.method === 'PUT')).toBe(false);
	});

	it('shows the proposals to a viewer without the decision buttons', async () => {
		setPrincipal({ role: 'viewer', actorId: 'v', actorType: 'user', csrfToken: 'tok' });
		serve({ 'GET /api/v1/filtering/mcp-proposals': () => ok({ proposals: [proposal] }) });
		render(RulesPage);
		expect(await screen.findByText('cdn.tinypass.com')).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: m.rules_proposal_allow() })).toBeNull();
		expect(screen.queryByRole('button', { name: m.rules_proposal_reject() })).toBeNull();
	});
});
