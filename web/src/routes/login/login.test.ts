// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import LoginPage from './+page.svelte';
import { m } from '$lib/paraglide/messages';
import { endSession } from '$lib/auth/state.svelte';

const navigation = vi.hoisted(() => ({ goto: vi.fn() }));
vi.mock('$app/navigation', () => navigation);

const pageState = vi.hoisted(() => ({
	url: new URL('http://localhost/login'),
}));
vi.mock('$app/state', () => ({ page: pageState }));

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const ok = (data: unknown): Response => json(200, { data });
const fail = (status: number, code: string, params?: Record<string, unknown>): Response =>
	json(status, params ? { error: { code, params } } : { error: { code } });

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	navigation.goto.mockReset();
	pageState.url = new URL('http://localhost/login');
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function setup(options?: { oidcEnabled?: boolean }) {
	const oidcEnabled = options?.oidcEnabled ?? false;
	fetchMock.mockImplementation(async (input) => {
		const url = String(input);
		if (url.includes('/auth/oidc/status')) return ok({ enabled: oidcEnabled });
		return fail(500, 'control_api.internal');
	});
	const user = userEvent.setup();
	render(LoginPage);
	return {
		user,
		username: screen.getByLabelText(m.login_username_label()),
		password: screen.getByLabelText(m.login_password_label()),
		submit: screen.getByRole('button', { name: m.login_submit() }),
	};
}

async function signIn(
	user: ReturnType<typeof userEvent.setup>,
	username: HTMLElement,
	password: HTMLElement,
	submit: HTMLElement,
) {
	await user.type(username, 'admin');
	await user.type(password, 'hunter2');
	await user.click(submit);
}

describe('login page', () => {
	it('disables the submit button while the local account is locked', async () => {
		const { user, username, password, submit } = setup();
		fetchMock.mockImplementation(async (input) => {
			const url = String(input);
			if (url.includes('/auth/oidc/status')) return ok({ enabled: false });
			return fail(423, 'control_api.auth.locked');
		});

		await signIn(user, username, password, submit);

		expect(await screen.findByText(m.login_locked_window())).toBeInTheDocument();
		expect(submit).toBeDisabled();
	});

	it('shows the generic rejected message and keeps the form usable', async () => {
		const { user, username, password, submit } = setup();
		fetchMock.mockImplementation(async (input) => {
			const url = String(input);
			if (url.includes('/auth/oidc/status')) return ok({ enabled: false });
			return fail(401, 'control_api.auth.local');
		});

		await signIn(user, username, password, submit);

		expect(await screen.findByText(m.error_control_api_auth_local())).toBeInTheDocument();
		expect(username).toHaveValue('admin');
		expect(password).toHaveValue('');
		expect(submit).toBeEnabled();
		expect(navigation.goto).not.toHaveBeenCalled();
	});

	it('renders error params as text, never as markup', async () => {
		const payload = '<img src="x" onerror="alert(1)">';
		const { user, username, password, submit } = setup();
		fetchMock.mockImplementation(async (input) => {
			const url = String(input);
			if (url.includes('/auth/oidc/status')) return ok({ enabled: false });
			return fail(403, 'control_api.auth.insufficient_scope', { required: payload });
		});

		await signIn(user, username, password, submit);

		expect(
			await screen.findByText(m.error_control_api_auth_insufficient_scope({ required: payload })),
		).toBeInTheDocument();
		expect(document.querySelector('img[src="x"]')).toBeNull();
		expect(document.querySelector('[onerror]')).toBeNull();
	});

	it('shows a translated OIDC error with a retry that starts the flow again', async () => {
		fetchMock.mockImplementation(async (input) => {
			const url = String(input);
			if (url.includes('/auth/oidc/status')) return ok({ enabled: true });
			if (url.includes('/auth/oidc/authorize-url')) return fail(500, 'control_api.auth.oidc');
			return fail(500, 'control_api.internal');
		});
		const user = userEvent.setup();
		render(LoginPage);

		await waitFor(() => {
			expect(screen.getByRole('button', { name: m.login_oidc_button() })).toBeInTheDocument();
		});

		await user.click(screen.getByRole('button', { name: m.login_oidc_button() }));
		expect(await screen.findByText(m.error_control_api_auth_oidc())).toBeInTheDocument();

		await user.click(screen.getByRole('button', { name: m.action_retry() }));
		expect(
			fetchMock.mock.calls.filter((call) => String(call[0]).includes('/auth/oidc/authorize-url'))
				.length,
		).toBeGreaterThanOrEqual(2);
	});

	it('hides the SSO button when OIDC is disabled', async () => {
		setup({ oidcEnabled: false });
		await waitFor(() => {
			expect(
				fetchMock.mock.calls.some((call) => String(call[0]).includes('/auth/oidc/status')),
			).toBe(true);
		});
		expect(screen.queryByRole('button', { name: m.login_oidc_button() })).toBeNull();
	});

	it('sends the password only in the login body and never in the URL', async () => {
		const { user, username, password, submit } = setup();
		fetchMock.mockImplementation(async (input) => {
			const url = String(input);
			if (url.includes('/auth/oidc/status')) return ok({ enabled: false });
			return fail(401, 'control_api.auth.local');
		});

		await signIn(user, username, password, submit);
		await screen.findByText(m.error_control_api_auth_local());

		const loginCall = fetchMock.mock.calls.find((call) =>
			String(call[0]).includes('/auth/local/login'),
		);
		expect(loginCall).toBeDefined();
		const [url, init] = loginCall ?? [];
		expect(String(url)).not.toContain('hunter2');
		expect((init as RequestInit).body).toBe(
			JSON.stringify({ username: 'admin', password: 'hunter2' }),
		);
	});
});
