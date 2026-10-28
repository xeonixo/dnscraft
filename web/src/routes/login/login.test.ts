// @vitest-environment jsdom
import '@testing-library/jest-dom/vitest';
import { cleanup, render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import LoginPage from './+page.svelte';
import { m } from '$lib/paraglide/messages';
import { endSession } from '$lib/auth/state.svelte';

const navigation = vi.hoisted(() => ({ goto: vi.fn() }));
vi.mock('$app/navigation', () => navigation);

const json = (status: number, body: unknown): Response =>
	new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
const fail = (status: number, code: string, params?: Record<string, unknown>): Response =>
	json(status, params ? { error: { code, params } } : { error: { code } });

let fetchMock: ReturnType<typeof vi.fn<typeof fetch>>;

beforeEach(() => {
	fetchMock = vi.fn<typeof fetch>();
	vi.stubGlobal('fetch', fetchMock);
	endSession();
	navigation.goto.mockReset();
});

afterEach(() => {
	cleanup();
	vi.unstubAllGlobals();
});

function setup() {
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
		fetchMock.mockResolvedValueOnce(fail(423, 'control_api.auth.locked'));
		const { user, username, password, submit } = setup();

		await signIn(user, username, password, submit);

		expect(await screen.findByText(m.login_locked_window())).toBeInTheDocument();
		expect(submit).toBeDisabled();
	});

	it('shows the generic rejected message and keeps the form usable', async () => {
		fetchMock.mockResolvedValueOnce(fail(401, 'control_api.auth.local'));
		const { user, username, password, submit } = setup();

		await signIn(user, username, password, submit);

		expect(await screen.findByText(m.error_control_api_auth_local())).toBeInTheDocument();
		expect(username).toHaveValue('admin');
		expect(password).toHaveValue('');
		expect(submit).toBeEnabled();
		expect(navigation.goto).not.toHaveBeenCalled();
	});

	it('renders error params as text, never as markup', async () => {
		const payload = '<img src="x" onerror="alert(1)">';
		fetchMock.mockResolvedValueOnce(
			fail(403, 'control_api.auth.insufficient_scope', { required: payload }),
		);
		const { user, username, password, submit } = setup();

		await signIn(user, username, password, submit);

		expect(
			await screen.findByText(m.error_control_api_auth_insufficient_scope({ required: payload })),
		).toBeInTheDocument();
		expect(document.querySelector('img')).toBeNull();
		expect(document.querySelector('[onerror]')).toBeNull();
	});

	it('shows a translated OIDC error with a retry that starts the flow again', async () => {
		fetchMock
			.mockResolvedValueOnce(fail(500, 'control_api.auth.oidc'))
			.mockResolvedValueOnce(fail(500, 'control_api.auth.oidc'));
		const { user } = setup();

		await user.click(screen.getByRole('button', { name: m.login_oidc_button() }));
		expect(await screen.findByText(m.error_control_api_auth_oidc())).toBeInTheDocument();

		await user.click(screen.getByRole('button', { name: m.action_retry() }));
		expect(fetchMock).toHaveBeenCalledTimes(2);
		expect(String(fetchMock.mock.calls[1]?.[0])).toBe('/api/v1/auth/oidc/authorize-url');
	});

	it('sends the password only in the login body and never in the URL', async () => {
		fetchMock.mockResolvedValueOnce(fail(401, 'control_api.auth.local'));
		const { user, username, password, submit } = setup();

		await signIn(user, username, password, submit);
		await screen.findByText(m.error_control_api_auth_local());

		const [url, init] = fetchMock.mock.calls[0] ?? [];
		expect(String(url)).not.toContain('hunter2');
		expect((init as RequestInit).body).toBe(
			JSON.stringify({ username: 'admin', password: 'hunter2' }),
		);
	});
});
