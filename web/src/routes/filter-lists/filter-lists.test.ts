// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import FilterListsPage from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { formatNumber } from '$lib/format';
import { getLocale } from '$lib/i18n/locale';
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

const HOUR = 3_600_000;
const ADS = {
	id: 'ads-main',
	name: 'AdGuard DNS',
	source: { url: 'https://adguard-dns.io/dns-filter.txt' },
	enabled: true,
	status: {
		rules_parsed: 41230,
		rules_skipped: 12,
		unique_contribution: 38210,
		last_success: new Date(Date.now() - 3 * HOUR).toISOString(),
		last_attempt: new Date(Date.now() - 3 * HOUR).toISOString(),
		error_code: null,
		http_status: 200,
	},
};
const TRACKERS = {
	id: 'trackers-main',
	name: 'Tracking protection',
	source: { url: 'https://example.com/lists/trackers.txt' },
	enabled: true,
	status: {
		rules_parsed: 8415,
		rules_skipped: 0,
		unique_contribution: 1790,
		last_success: new Date(Date.now() - 50 * HOUR).toISOString(),
		last_attempt: new Date(Date.now() - 0.5 * HOUR).toISOString(),
		error_code: 'filter_list.fetch_failed',
		http_status: 503,
	},
};
const LEGACY = {
	id: 'legacy-hosts',
	name: 'Legacy hosts',
	source: { url: 'https://example.com/lists/hosts.txt' },
	enabled: false,
};
const NEW = { id: 'fresh', name: 'Fresh', source: { file: '/lists/f.txt' }, enabled: true };

function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'GET /api/v1/filter-lists': () => ok({ filter_lists: [ADS, TRACKERS, LEGACY, NEW] }),
		'GET /api/v1/filter-sets': () =>
			ok({
				filter_sets: [
					{
						id: 'default',
						name: 'Standard',
						lists: ['ads-main', 'trackers-main'],
						custom_rules: '',
						services: [],
						block_mode: 'refused',
					},
				],
			}),
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

describe('filter-lists page', () => {
	it('shows the total of active lists and each list with its rule count and status', async () => {
		render(FilterListsPage);
		const locale = getLocale();
		expect(
			await screen.findByText(
				m.filter_lists_total_other({
					rules: formatNumber(49645, locale),
					count: formatNumber(2, locale),
				}),
			),
		).toBeInTheDocument();

		const adsRow = (await screen.findByText('AdGuard DNS')).closest('.list-row') as HTMLElement;
		expect(within(adsRow).getByText('adguard-dns.io')).toBeInTheDocument();
		expect(
			within(adsRow).getByText(
				m.filter_sets_count_rules_other({ count: formatNumber(41230, getLocale()) }),
			),
		).toBeInTheDocument();
		expect(
			within(adsRow).getByText(m.filter_lists_status_skipped({ count: '12' }), { exact: false }),
		).toBeInTheDocument();
	});

	it('qualifies the total when an enabled list failed its last update, but keeps counting its rules', async () => {
		render(FilterListsPage);
		const locale = getLocale();
		expect(
			await screen.findByText(
				m.filter_lists_total_other({
					rules: formatNumber(49645, locale),
					count: formatNumber(2, locale),
				}),
			),
		).toBeInTheDocument();
		expect(
			screen.getByText(m.filter_lists_failed_last_update({ count: formatNumber(1, locale) }), {
				exact: false,
			}),
		).toBeInTheDocument();
	});

	it('marks a failed update with text and the translated error, keeping the last good count', async () => {
		render(FilterListsPage);
		const row = (await screen.findByText('Tracking protection')).closest(
			'.list-row',
		) as HTMLElement;
		expect(
			within(row).getByText(m.filter_lists_status_failed(), { exact: false }),
		).toBeInTheDocument();
		expect(
			within(row).getByText(m.error_filter_list_fetch_failed(), { exact: false }),
		).toBeInTheDocument();
		expect(
			within(row).getByText(m.filter_lists_status_http({ status: '503' }), { exact: false }),
		).toBeInTheDocument();
	});

	it('says disabled and never-fetched lists as text', async () => {
		render(FilterListsPage);
		const legacy = (await screen.findByText('Legacy hosts')).closest('.list-row') as HTMLElement;
		expect(within(legacy).getByText(m.filter_list_disabled())).toBeInTheDocument();
		const fresh = (await screen.findByText('Fresh')).closest('.list-row') as HTMLElement;
		expect(within(fresh).getByText(m.filter_lists_status_pending())).toBeInTheDocument();
	});

	it('shows which filter sets use a list, or that none does', async () => {
		render(FilterListsPage);
		const ads = (await screen.findByText('AdGuard DNS')).closest('.list-row') as HTMLElement;
		expect(
			await within(ads).findByText(m.filter_lists_used_by({ sets: 'Standard' })),
		).toBeInTheDocument();
		const legacy = (await screen.findByText('Legacy hosts')).closest('.list-row') as HTMLElement;
		expect(await within(legacy).findByText(m.filter_lists_used_by_none())).toBeInTheDocument();
	});

	it('enables a list from its switch with a body that omits the engine status', async () => {
		serve({
			'PUT /api/v1/filter-lists': () => ok({ version: 4, filter_list: LEGACY, created: false }),
		});
		render(FilterListsPage);
		const toggle = await screen.findByRole('switch', {
			name: m.filter_lists_toggle_label({ name: 'Legacy hosts' }),
		});
		fireEvent.click(toggle);
		await waitFor(() => expect(bodyOf('PUT')).toBeDefined());
		expect(bodyOf('PUT')).toEqual({
			id: 'legacy-hosts',
			name: 'Legacy hosts',
			source: { url: 'https://example.com/lists/hosts.txt' },
			enabled: true,
		});
	});

	it('puts the switch back and shows the error when saving fails', async () => {
		serve({
			'PUT /api/v1/filter-lists': () =>
				json(409, { error: { code: 'control_api.config.version', params: {} } }),
		});
		render(FilterListsPage);
		const toggle = (await screen.findByRole('switch', {
			name: m.filter_lists_toggle_label({ name: 'Legacy hosts' }),
		})) as HTMLInputElement;
		fireEvent.click(toggle);
		await waitFor(() => expect(toggle.checked).toBe(false));
		expect(await screen.findByRole('alert')).toBeInTheDocument();
	});

	it('moves delete into the edit sheet behind a confirmation', async () => {
		serve({
			'DELETE /api/v1/filter-lists': () => ok({ version: 5, deleted: true, id: 'fresh' }),
		});
		render(FilterListsPage);
		expect(screen.queryByRole('button', { name: m.action_delete() })).toBeNull();
		const fresh = (await screen.findByText('Fresh')).closest('.list-row') as HTMLElement;
		await userEvent.click(within(fresh).getByRole('button', { name: m.action_edit() }));
		const sheet = await screen.findByRole('dialog');
		await userEvent.click(within(sheet).getByRole('button', { name: m.filter_lists_delete() }));
		expect(within(sheet).getByText(m.filter_lists_delete_question())).toBeInTheDocument();
		await userEvent.click(within(sheet).getByRole('button', { name: m.action_delete() }));
		await waitFor(() => expect(bodyOf('DELETE')).toEqual({ id: 'fresh' }));
	});
});
