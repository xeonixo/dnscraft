// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import FilterSetsPage from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { m } from '$lib/paraglide/messages';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });

type Handler = (init?: RequestInit) => Response;

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;

const LIST = {
	id: 'ads-main',
	name: 'AdGuard DNS',
	source: { url: 'https://example.test/a.txt' },
	enabled: true,
};
const TRACKERS = {
	id: 'trackers-main',
	name: 'Trackers',
	source: { file: '/lists/t.txt' },
	enabled: true,
};

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'GET /api/v1/filter-sets': () =>
			ok({
				filter_sets: [
					{
						id: 'default',
						name: 'Default',
						lists: ['ads-main'],
						custom_rules: '||ads.example^\n! comment\n||tracker.example^',
						services: [],
						block_mode: 'refused',
						mcp_rules: [],
					},
				],
			}),
		'GET /api/v1/filter-lists': () => ok({ filter_lists: [LIST, TRACKERS] }),
		...overrides,
	};
	fetchMock.mockImplementation(async (input, init) => {
		const url = String(input);
		const handler = handlers[`${init?.method ?? 'GET'} ${url.split('?')[0]}`];
		return handler ? handler(init) : json(404, { error: { code: 'control_api.not_found' } });
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

describe('filter-sets page', () => {
	it('explains the page and summarises each set with its non-zero counts only', async () => {
		render(FilterSetsPage);
		expect(await screen.findByText(m.filter_sets_intro(), { exact: false })).toBeInTheDocument();
		const summary = [
			m.filter_sets_count_lists_one({ count: 1 }),
			m.filter_sets_count_rules_other({ count: 2 }),
		].join(' · ');
		expect(await screen.findByText(summary)).toBeInTheDocument();
		expect(screen.queryByText(/Blockmodus/)).toBeNull();
	});

	it('shows the block mode on a card only when it is not the default', async () => {
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'nx',
							name: 'Nx',
							lists: [],
							custom_rules: '',
							services: [],
							block_mode: 'nxdomain',
						},
					],
				}),
		});
		render(FilterSetsPage);
		expect(
			await screen.findByText(m.filter_sets_summary_mode({ mode: m.filter_block_nxdomain() })),
		).toBeInTheDocument();
	});

	it('says a set with nothing in it is not configured yet', async () => {
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'empty',
							name: 'Empty',
							lists: [],
							custom_rules: '',
							services: [],
							block_mode: 'refused',
						},
					],
				}),
		});
		render(FilterSetsPage);
		expect(await screen.findByText(m.filter_sets_nothing_configured())).toBeInTheDocument();
	});

	it('lists the profiles that use a set on its card, capped at three with a count', async () => {
		serve({
			'GET /api/v1/config': () =>
				ok({
					version: 3,
					config: {
						policy: {
							profiles: [
								{ id: 'kids', filter_set: 'default' },
								{ id: 'office', filter_set: 'default' },
								{ id: 'guest', filter_set: 'default' },
								{ id: 'lab', filter_set: 'default' },
								{ id: 'other', filter_set: 'lan' },
							],
						},
					},
				}),
		});
		render(FilterSetsPage);
		expect(
			await screen.findByText(
				`${m.filter_sets_used_by({ profiles: 'kids, office, guest' })} ${m.filter_sets_used_by_more({ count: 1 })}`,
			),
		).toBeInTheDocument();
	});

	it('says when no profile uses a set', async () => {
		serve({
			'GET /api/v1/config': () =>
				ok({ version: 3, config: { policy: { profiles: [{ id: 'kids', filter_set: 'lan' }] } } }),
		});
		render(FilterSetsPage);
		expect(await screen.findByText(m.filter_sets_used_by_none())).toBeInTheDocument();
	});

	it('leaves the usage line off silently when the profile load fails', async () => {
		render(FilterSetsPage);
		expect(await screen.findByText(/Default/)).toBeInTheDocument();
		await waitFor(() =>
			expect(fetchMock.mock.calls.some(([url]) => String(url).endsWith('/api/v1/config'))).toBe(
				true,
			),
		);
		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(screen.queryByText(m.filter_sets_used_by_none())).toBeNull();
		expect(screen.queryByText(/Genutzt von/)).toBeNull();
		expect(screen.queryByRole('alert')).toBeNull();
	});

	it('keeps the destructive action out of the rows and confirms it in the edit sheet', async () => {
		handlers['DELETE /api/v1/filter-sets'] = () => ok({ version: 5, deleted: true, id: 'default' });
		const user = userEvent.setup();
		render(FilterSetsPage);
		await user.click(await screen.findByRole('button', { name: /Default/ }));

		const dialog = screen.getByRole('dialog');
		expect(within(dialog).queryByRole('button', { name: m.action_delete() })).toBeNull();
		await user.click(within(dialog).getByRole('button', { name: m.filter_sets_delete() }));
		expect(within(dialog).getByText(m.filter_sets_delete_question())).toBeInTheDocument();
		expect(bodyOf('DELETE')).toBeUndefined();

		await user.click(within(dialog).getByRole('button', { name: m.action_delete() }));
		await waitFor(() => expect(bodyOf('DELETE')).toEqual({ id: 'default' }));
	});

	it('truncates a 150-character hostile name instead of overflowing the row', async () => {
		const longName = 'x'.repeat(150);
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'long',
							name: longName,
							lists: [],
							custom_rules: '',
							services: [],
							block_mode: 'refused',
						},
					],
				}),
		});
		render(FilterSetsPage);
		expect(await screen.findByText(/x{100,}…$/)).toBeInTheDocument();
		expect(screen.queryByText(longName)).toBeNull();
	});

	it('toggles a list and keeps a custom IP block mode when saving', async () => {
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'lan',
							name: 'Lan',
							lists: ['ads-main'],
							custom_rules: '',
							services: ['social-video'],
							block_mode: { custom_ip: '192.0.2.1' },
						},
					],
				}),
		});
		handlers['PUT /api/v1/filter-sets'] = () => ok({ version: 6, filter_set: {}, created: false });
		const user = userEvent.setup();
		render(FilterSetsPage);
		await user.click(await screen.findByRole('button', { name: /Lan/ }));

		const dialog = screen.getByRole('dialog');
		expect(await within(dialog).findByRole('switch', { name: 'AdGuard DNS' })).toBeChecked();
		within(dialog).getByRole('switch', { name: 'Trackers' }).focus();
		await user.keyboard(' ');
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));

		await waitFor(() =>
			expect(bodyOf('PUT')).toEqual({
				id: 'lan',
				name: 'Lan',
				lists: ['ads-main', 'trackers-main'],
				custom_rules: '',
				services: ['social-video'],
				block_mode: { custom_ip: '192.0.2.1' },
			}),
		);
	});

	it('adds a rule from the guided form under the Rules section', async () => {
		handlers['PUT /api/v1/filter-sets'] = () => ok({ version: 6, filter_set: {}, created: false });
		const user = userEvent.setup();
		render(FilterSetsPage);
		await user.click(await screen.findByRole('button', { name: /Default/ }));
		const dialog = screen.getByRole('dialog');
		await user.type(within(dialog).getByLabelText(m.filter_rule_domain()), 'news.example');
		await user.click(within(dialog).getByRole('button', { name: m.filter_rule_add_button() }));
		await user.click(within(dialog).getByRole('button', { name: m.action_save() }));
		await waitFor(() =>
			expect(bodyOf('PUT')?.custom_rules).toBe(
				'||ads.example^\n! comment\n||tracker.example^\n||news.example^',
			),
		);
	});

	it('explains an empty page and offers the add action', async () => {
		serve({ 'GET /api/v1/filter-sets': () => ok({ filter_sets: [] }) });
		render(FilterSetsPage);
		expect(await screen.findByText(m.filter_sets_empty())).toBeInTheDocument();
		expect(screen.getAllByRole('button', { name: m.filter_sets_add() }).length).toBeGreaterThan(0);
	});

	it('shows no add action and no editor to a viewer', async () => {
		setPrincipal({ role: 'viewer', actorId: 'bob', actorType: 'user', csrfToken: null });
		render(FilterSetsPage);
		expect(await screen.findByText(/Default/)).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: m.filter_sets_add() })).toBeNull();
		expect(screen.queryByRole('button', { name: /Default/ })).toBeNull();
	});

	it('shows each set as a card with its name, summary, first list names and a chevron', async () => {
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'many',
							name: 'Many',
							lists: ['ads-main', 'trackers-main', 'unknown-list', 'extra-list'],
							custom_rules: '',
							services: [],
							block_mode: 'refused',
						},
					],
				}),
		});
		render(FilterSetsPage);
		const card = await screen.findByRole('button', { name: /Many/ });
		expect(within(card).getByText('Many')).toBeInTheDocument();
		expect(
			within(card).getByText(
				`AdGuard DNS, Trackers, unknown-list ${m.filter_sets_lists_more({ count: 1 })}`,
			),
		).toBeInTheDocument();
		expect(card.querySelector('.chev svg')).not.toBeNull();
	});

	it('shows no chevron on the read-only cards of a viewer', async () => {
		setPrincipal({ role: 'viewer', actorId: 'bob', actorType: 'user', csrfToken: null });
		const { container } = render(FilterSetsPage);
		expect(await screen.findByText('Default')).toBeInTheDocument();
		expect(container.querySelector('.chev')).toBeNull();
	});

	it('pins the action bar in a footer outside the scrolling body', async () => {
		const user = userEvent.setup();
		render(FilterSetsPage);
		await user.click(await screen.findByRole('button', { name: /Default/ }));
		const dialog = screen.getByRole('dialog');
		const body = dialog.querySelector('.sheet-body');
		expect(body).not.toBeNull();
		const save = within(dialog).getByRole('button', { name: m.action_save() });
		const cancel = within(dialog).getByRole('button', { name: m.action_cancel() });
		expect(save.closest('.sheet-footer')).not.toBeNull();
		expect(cancel.closest('.sheet-footer')).not.toBeNull();
		expect(body?.contains(save)).toBe(false);
		expect(
			within(body as HTMLElement).getByLabelText(m.filter_sets_name_label()),
		).toBeInTheDocument();
	});

	it('labels block and allow rules and shows their domain instead of the raw prefix', async () => {
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'rules',
							name: 'Rules',
							lists: [],
							custom_rules: '||ads.example^\n@@||safe.example^\n! comment',
							services: [],
							block_mode: 'refused',
						},
					],
				}),
		});
		const user = userEvent.setup();
		render(FilterSetsPage);
		await user.click(await screen.findByRole('button', { name: /Rules/ }));
		const dialog = screen.getByRole('dialog');
		expect(within(dialog).getByText('ads.example')).toBeInTheDocument();
		expect(within(dialog).getByText('safe.example')).toBeInTheDocument();
		expect(within(dialog).queryByText('||ads.example^')).toBeNull();
		expect(within(dialog).getByText(m.filter_rule_kind_block())).toBeInTheDocument();
		expect(within(dialog).getByText(m.filter_rule_kind_allow())).toBeInTheDocument();
		expect(within(dialog).getByText('! comment')).toBeInTheDocument();
	});

	it('keeps the guided rule form on one compact row with the subdomain switch below', async () => {
		const user = userEvent.setup();
		render(FilterSetsPage);
		await user.click(await screen.findByRole('button', { name: /Default/ }));
		const dialog = screen.getByRole('dialog');
		const form = dialog.querySelector('.rule-form');
		expect(form).not.toBeNull();
		const domain = within(form as HTMLElement).getByLabelText(m.filter_rule_domain());
		expect(domain).toBeInTheDocument();
		expect(
			within(form as HTMLElement).getByRole('button', { name: m.filter_rule_add_button() }),
		).toBeInTheDocument();
		expect(
			within(form as HTMLElement).getByRole('radiogroup', { name: m.filter_rule_action() }),
		).toBeInTheDocument();
		expect(
			within(dialog).getByRole('switch', { name: m.filter_rule_subdomains() }),
		).toBeInTheDocument();
	});

	it('shows the enabled services as a read-only line under the services heading', async () => {
		serve({
			'GET /api/v1/filter-sets': () =>
				ok({
					filter_sets: [
						{
							id: 'svc',
							name: 'Svc',
							lists: [],
							custom_rules: '',
							services: ['social-video', 'gaming'],
							block_mode: 'refused',
						},
					],
				}),
		});
		const user = userEvent.setup();
		render(FilterSetsPage);
		await user.click(await screen.findByRole('button', { name: /Svc/ }));
		const dialog = screen.getByRole('dialog');
		expect(
			within(dialog).getByText(
				m.filter_sets_services_enabled({ services: 'social-video, gaming' }),
			),
		).toBeInTheDocument();
		expect(within(dialog).getByText(m.filter_sets_manage_services())).toBeInTheDocument();
	});
});
