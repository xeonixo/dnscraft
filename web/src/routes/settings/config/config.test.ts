// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import Page from './+page.svelte';
import { endSession, setPrincipal } from '$lib/auth/state.svelte';
import { parseConfigText } from '$lib/config/view';
import { m } from '$lib/paraglide/messages';
import { live } from '$lib/live.svelte';

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string, params?: Record<string, unknown>): Response =>
	json(status, params ? { error: { code, params } } : { error: { code } });

type Handler = (init: RequestInit, url: URL) => Response | Promise<Response>;

const rule = {
	id: 'mcp-rule-0001',
	domain: 'example.com',
	include_subdomains: true,
	created_at: '2026-10-26T08:00:00Z',
	expires_at: null,
	token_id: null,
};

/** The stored snapshot the screen loads first. Secrets are never part of it. */
function storedConfig(): Record<string, unknown> {
	return {
		filtering: {
			sets: [
				{
					id: 'default',
					name: 'Standard',
					lists: ['ads-main'],
					custom_rules: [],
					services: [],
					block_mode: 'refused',
					mcp_rules: [rule],
				},
			],
		},
		clients: { manual: [] },
		policy: {
			views: [],
			profiles: [{ id: 'default', filter_set: 'default' }],
		},
		listeners: { items: [] },
		tls: {},
	};
}

const VERSIONS = {
	current_version: 12,
	versions: [
		{ version: 12, created_at: '2026-10-27T08:00:00Z' },
		{ version: 11, created_at: '2026-10-26T20:00:00Z' },
	],
	has_more: false,
	next_offset: null,
};

const NO_FINDINGS = {
	valid: true,
	config_version: 12,
	errors: [],
	warnings: [],
	diff: emptyDiff(),
};

function emptyDiff() {
	return { changed_sections: [], added: [], removed: [], changed: [] };
}

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;
let handlers: Record<string, Handler>;
let stored: Record<string, unknown>;

/** Serves the configuration routes; a test overrides only what it needs. */
function serve(overrides: Record<string, Handler> = {}): void {
	handlers = {
		'GET /api/v1/config': () => ok({ version: 12, config: stored }),
		'GET /api/v1/config/versions': () => ok(VERSIONS),
		'POST /api/v1/config/validate': () => ok(NO_FINDINGS),
		...overrides,
	};
	fetchMock.mockImplementation(async (input, init) => {
		const url = new URL(String(input), 'http://localhost');
		const key = `${init?.method ?? 'GET'} ${url.pathname}`;
		const handler = handlers[key];
		return handler ? handler(init ?? {}, url) : fail(404, 'control_api.not_found');
	});
}

/** The requests made so far for one method and path, with their init objects. */
function calls(method: string, path: string): RequestInit[] {
	return fetchMock.mock.calls
		.filter(([input, init]) => {
			const url = new URL(String(input), 'http://localhost');
			return (init?.method ?? 'GET') === method && url.pathname === path;
		})
		.map(([, init]) => init ?? {});
}

function headerOf(init: RequestInit, name: string): string | null {
	return new Headers(init.headers).get(name);
}

function editor(): HTMLTextAreaElement {
	return screen.getByLabelText(m.config_editor_label()) as HTMLTextAreaElement;
}

/** Replaces the editor content, as a paste or a typed edit would. */
function setText(value: string): void {
	fireEvent.input(editor(), { target: { value } });
}

function save(): HTMLElement {
	return screen.getByRole('button', { name: m.action_save() });
}

function checkButton(): HTMLElement {
	return screen.getByRole('button', { name: m.config_check() });
}

function setup(role: 'admin' | 'viewer' = 'admin') {
	setPrincipal({ role, actorId: 'admin', actorType: 'user', csrfToken: 'csrf-token' });
	const user = userEvent.setup();
	render(Page);
	return { user };
}

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	stored = storedConfig();
	serve();
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe('configuration screen for a viewer', () => {
	it('shows the read-only note and makes no configuration call', () => {
		setup('viewer');
		expect(screen.getByText(m.config_viewer_only())).toBeInTheDocument();
		expect(screen.queryByLabelText(m.config_editor_label())).toBeNull();
		expect(screen.queryByRole('button', { name: m.action_save() })).toBeNull();
		expect(screen.queryByRole('button', { name: m.config_check() })).toBeNull();
		expect(screen.queryByRole('button', { name: m.config_rollback() })).toBeNull();
		expect(document.querySelector('input[type="file"]')).toBeNull();
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it('still says that backups are not available on this node', () => {
		setup('viewer');
		expect(screen.getByText(m.config_backups_unavailable())).toBeInTheDocument();
	});
});

describe('configuration editor for an administrator', () => {
	it('loads the stored configuration and its version into the editor', async () => {
		setup();
		await screen.findByLabelText(m.config_editor_label());
		// The version shows in the editor header and in the version list.
		expect(screen.getAllByText(m.config_version_label({ version: 12 }))).not.toHaveLength(0);
		expect(JSON.parse(editor().value)).toEqual(stored);
		expect(editor()).toHaveAttribute('spellcheck', 'false');
	});

	it('shows errors, warnings and the change summary, and blocks saving the same content', async () => {
		serve({
			'POST /api/v1/config/validate': () =>
				ok({
					valid: false,
					config_version: 12,
					errors: [
						{
							code: 'policy.config.unknown_filter_set',
							path: 'policy.profiles[0].filter_set',
							params: { path: 'policy.profiles[0].filter_set' },
						},
					],
					warnings: [
						{ code: 'filtering.config.no_lists', path: 'filtering.sets[0].lists', params: {} },
					],
					diff: {
						changed_sections: ['policy'],
						added: [],
						removed: [],
						changed: ['policy.profiles'],
					},
				}),
		});
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());
		setText(JSON.stringify({ ...stored, policy: { profiles: [{ id: 'x', filter_set: 'nope' }] } }));

		await user.click(checkButton());

		const sheet = await screen.findByRole('dialog', { name: m.config_check_title() });
		// Unknown codes show their raw code; the field path is linked beneath it.
		expect(within(sheet).getByText('policy.config.unknown_filter_set')).toBeInTheDocument();
		expect(
			within(sheet).getByText(m.config_finding_path({ path: 'policy.profiles[0].filter_set' })),
		).toBeInTheDocument();
		expect(within(sheet).getByText('filtering.config.no_lists')).toBeInTheDocument();
		expect(within(sheet).getByText('policy.profiles')).toBeInTheDocument();
		expect(within(sheet).getByText(m.config_check_footer())).toBeInTheDocument();
		expect(save()).toBeDisabled();

		await user.click(within(sheet).getByRole('button', { name: m.action_close() }));
		expect(screen.queryByRole('dialog', { name: m.config_check_title() })).toBeNull();
		expect(save()).toBeDisabled();
		expect(screen.getByText(m.config_check_errors({ count: 1 }))).toBeInTheDocument();
	});

	it('enables saving after an edit and sends If-Match with the loaded version', async () => {
		serve({
			'PUT /api/v1/config': () => ok({ version: 13 }),
		});
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());
		const next = { ...stored, clients: { manual: [{ id: 'nas' }] } };
		setText(JSON.stringify(next));

		await user.click(save());

		const [put] = calls('PUT', '/api/v1/config');
		expect(put).toBeDefined();
		expect(headerOf(put, 'If-Match')).toBe('12');
		expect(headerOf(put, 'X-CSRF-Token')).toBe('csrf-token');
		expect(JSON.parse(String(put.body))).toEqual(next);
		await waitFor(() => expect(live.message).toBe(m.config_saved({ version: 13 })));
	});

	it('does not send a PUT when the JSON is malformed and says where it breaks', async () => {
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());
		const broken = '{\n  "filtering" 1\n}';
		setText(broken);

		const located = parseConfigText(broken);
		if (located.ok) throw new Error('the broken JSON must not parse');
		// The message names the line and column only when the engine reports a position.
		const expected =
			located.line === null || located.column === null
				? m.config_parse_error_generic()
				: m.config_parse_error({ line: located.line, column: located.column });
		expect(await screen.findByText(expected)).toBeInTheDocument();
		expect(editor()).toHaveAttribute('aria-invalid', 'true');
		expect(save()).toBeDisabled();
		expect(checkButton()).toBeDisabled();
		await user.click(save());
		expect(calls('PUT', '/api/v1/config')).toHaveLength(0);
	});

	it('keeps the typed text on a version conflict and restores it after a reload', async () => {
		let reads = 0;
		serve({
			'PUT /api/v1/config': () => fail(409, 'control_api.config.version'),
			'GET /api/v1/config': () => {
				reads += 1;
				// The first read is the page load; after the conflict the server holds a newer version.
				return reads === 1
					? ok({ version: 12, config: stored })
					: ok({
							version: 13,
							config: { ...stored, clients: { manual: [{ id: 'server-side' }] } },
						});
			},
		});
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());
		const mine = JSON.stringify({ ...stored, clients: { manual: [{ id: 'mine' }] } });
		setText(mine);

		await user.click(save());

		const notice = await screen.findByRole('alert');
		expect(within(notice).getByText(m.config_conflict_body())).toBeInTheDocument();
		expect(editor().value).toBe(mine);

		await user.click(within(notice).getByRole('button', { name: m.config_reload() }));

		await waitFor(() => expect(editor().value).toContain('server-side'));
		const kept = screen.getByRole('textbox', {
			name: m.config_kept_title(),
		}) as HTMLTextAreaElement;
		expect(kept.value).toBe(mine);

		await user.click(screen.getByRole('button', { name: m.config_restore_kept() }));
		expect(editor().value).toBe(mine);
	});

	it('shows the mcp_rules of an omitted field as carried over and an explicit empty list as deleted', async () => {
		serve({
			'POST /api/v1/config/validate': () => ok(NO_FINDINGS),
		});
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());

		const omitted = structuredClone(stored) as { filtering: { sets: Record<string, unknown>[] } };
		delete omitted.filtering.sets[0].mcp_rules;
		setText(JSON.stringify(omitted));
		await user.click(checkButton());
		let sheet = await screen.findByRole('dialog', { name: m.config_check_title() });
		expect(
			within(sheet).getByText(m.config_mcp_carried({ set: 'default', count: 1 })),
		).toBeInTheDocument();
		expect(
			within(sheet).queryByText(m.config_mcp_deleted({ set: 'default', count: 1 })),
		).toBeNull();
		await user.click(within(sheet).getByRole('button', { name: m.action_close() }));

		const emptied = structuredClone(stored) as { filtering: { sets: Record<string, unknown>[] } };
		emptied.filtering.sets[0].mcp_rules = [];
		setText(JSON.stringify(emptied));
		await user.click(checkButton());
		sheet = await screen.findByRole('dialog', { name: m.config_check_title() });
		expect(
			within(sheet).getByText(m.config_mcp_deleted({ set: 'default', count: 1 })),
		).toBeInTheDocument();
		expect(
			within(sheet).queryByText(m.config_mcp_carried({ set: 'default', count: 1 })),
		).toBeNull();
	});

	it('renders hostile values from the candidate as inert text', async () => {
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());
		const hostile = '<img src=x onerror=alert(1)>';
		const candidate = {
			...stored,
			filtering: {
				sets: [{ id: hostile, lists: ['x'], mcp_rules: [{ ...rule, domain: hostile }] }],
			},
			policy: { views: [], profiles: [] },
		};
		setText(JSON.stringify(candidate));

		await user.click(checkButton());

		const sheet = await screen.findByRole('dialog', { name: m.config_check_title() });
		expect(
			within(sheet).getByText(m.config_mcp_replaced({ set: hostile, count: 1 })),
		).toBeInTheDocument();
		expect(document.querySelector('img')).toBeNull();
		expect(document.querySelector('[onerror]')).toBeNull();
	});

	it('loads an imported file into the editor, checks it and never saves it', async () => {
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());
		const file = new File(
			[JSON.stringify({ ...stored, clients: { manual: [{ id: 'file' }] } })],
			'config.json',
			{
				type: 'application/json',
			},
		);
		const input = document.querySelector('input[type="file"]') as HTMLInputElement;

		await user.upload(input, file);

		await waitFor(() => expect(editor().value).toContain('"file"'));
		expect(calls('PUT', '/api/v1/config')).toHaveLength(0);
		await waitFor(() => expect(calls('POST', '/api/v1/config/validate')).toHaveLength(1));
		expect(live.message).toBe(m.config_import_loaded());
	});

	it('exports the loaded configuration as a JSON file named after its version', async () => {
		const createObjectURL = vi.fn<(blob: Blob) => string>(() => 'blob:dnscraft-test');
		const revokeObjectURL = vi.fn();
		Object.assign(URL, { createObjectURL, revokeObjectURL });
		const clicked: { download: string; href: string }[] = [];
		vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
			this: HTMLAnchorElement,
		) {
			clicked.push({ download: this.download, href: this.href });
		});
		const { user } = setup();
		await screen.findByLabelText(m.config_editor_label());

		await user.click(screen.getByRole('button', { name: m.config_export() }));

		expect(clicked).toEqual([{ download: 'dnscraft-config-v12.json', href: 'blob:dnscraft-test' }]);
		const blob = createObjectURL.mock.calls[0]?.[0] as Blob;
		expect(blob.type).toBe('application/json');
		expect(JSON.parse(await blob.text())).toEqual(stored);
		expect(calls('PUT', '/api/v1/config')).toHaveLength(0);
	});
});

describe('versions and rollback', () => {
	it('lists the stored versions and marks the current one', async () => {
		setup();
		expect(await screen.findByText(m.config_version_current())).toBeInTheDocument();
		expect(screen.getAllByRole('button', { name: m.config_rollback() })).toHaveLength(1);
	});

	it('confirms the rollback in a sheet with Cancel focused first, then posts it', async () => {
		serve({
			'POST /api/v1/config/versions/11/rollback': () => ok({ version: 13, restored_from: 11 }),
		});
		const { user } = setup();
		const trigger = await screen.findByRole('button', { name: m.config_rollback() });

		await user.click(trigger);

		const sheet = await screen.findByRole('dialog', {
			name: m.config_rollback_title({ version: 11 }),
		});
		expect(within(sheet).getByText(m.config_rollback_body({ version: 11 }))).toBeInTheDocument();
		expect(within(sheet).getByRole('button', { name: m.action_cancel() })).toHaveFocus();
		expect(calls('POST', '/api/v1/config/versions/11/rollback')).toHaveLength(0);

		await user.click(within(sheet).getByRole('button', { name: m.config_rollback_confirm() }));

		const [post] = calls('POST', '/api/v1/config/versions/11/rollback');
		expect(post).toBeDefined();
		expect(headerOf(post, 'If-Match')).toBe('12');
		expect(headerOf(post, 'X-CSRF-Token')).toBe('csrf-token');
		await waitFor(() =>
			expect(
				screen.queryByRole('dialog', { name: m.config_rollback_title({ version: 11 }) }),
			).toBeNull(),
		);
		expect(trigger).toHaveFocus();
	});

	it('closes the rollback sheet on Escape without posting', async () => {
		const { user } = setup();
		await user.click(await screen.findByRole('button', { name: m.config_rollback() }));
		await screen.findByRole('dialog', { name: m.config_rollback_title({ version: 11 }) });

		await user.keyboard('{Escape}');

		expect(
			screen.queryByRole('dialog', { name: m.config_rollback_title({ version: 11 }) }),
		).toBeNull();
		expect(calls('POST', '/api/v1/config/versions/11/rollback')).toHaveLength(0);
	});
});
