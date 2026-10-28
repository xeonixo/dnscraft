import { describe, expect, it } from 'vitest';
import {
	clientsPatchFromForm,
	formFromClients,
	isSelfSyncOwner,
	pollSecondsOf,
	tlsChoiceOf,
	type ClientsUnifiForm,
} from './unifi';

describe('pollSecondsOf', () => {
	it('parses second, minute and hour durations', () => {
		expect(pollSecondsOf('60s')).toBe(60);
		expect(pollSecondsOf('2m')).toBe(120);
		expect(pollSecondsOf('1h')).toBe(3600);
		expect(pollSecondsOf(45)).toBe(45);
		expect(pollSecondsOf('nope', 30)).toBe(30);
	});
});

describe('tlsChoiceOf', () => {
	it('prefers insecure, then pin, then ca file, else system CA', () => {
		expect(tlsChoiceOf({ insecure_skip_verify: true })).toBe('insecure');
		expect(tlsChoiceOf({ tls_pin_sha256: 'sha256:ab' })).toBe('pin');
		expect(tlsChoiceOf({ ca_file: '/ca.pem' })).toBe('ca_file');
		expect(tlsChoiceOf({})).toBe('secure');
	});
});

describe('formFromClients / clientsPatchFromForm', () => {
	it('round-trips UniFi profiles and bindings', () => {
		const form = formFromClients(
			{
				local_domain: 'lan.example',
				local_domain_mode: 'config',
				unifi_profiles: [
					{
						id: 'home',
						sync_owner: 'master',
						enabled: true,
						base_url: 'https://192.0.2.1',
						site_id: 'site-1',
						poll_interval: '90s',
						classic_clients: false,
						tls_pin_sha256:
							'sha256:abcdefghijklmnopqrstuvwxyz0123456789abcdef0123456789abcdef01',
						ca_file: null,
						insecure_skip_verify: false,
					},
				],
				unifi_bindings: { master: 'home', garage: 'home' },
			},
			{
				profiles: [
					{
						id: 'home',
						sync_owner: 'master',
						enabled: true,
						base_url: 'https://192.0.2.1',
						site_id: 'site-1',
						poll_interval: '90s',
						classic_clients: false,
						tls_pin_sha256:
							'sha256:abcdefghijklmnopqrstuvwxyz0123456789abcdef0123456789abcdef01',
						has_api_key: true,
					},
				],
				bindings: { master: 'home', garage: 'home' },
			},
		);

		expect(form.profiles[0]).toMatchObject({
			id: 'home',
			enabled: true,
			base_url: 'https://192.0.2.1',
			site_id: 'site-1',
			poll_seconds: 90,
			classic_clients: false,
			tls: 'pin',
			sync_owner: 'master',
			has_api_key: true,
		});
		expect(form.local_domain).toBe('lan.example');
		expect(form.local_domain_mode).toBe('config');
		expect(form.bindings).toEqual({ master: 'home', garage: 'home' });
		expect(isSelfSyncOwner(form, 'master')).toBe(true);
		expect(isSelfSyncOwner(form, 'garage')).toBe(false);

		expect(clientsPatchFromForm(form)).toEqual({
			local_domain: 'lan.example',
			local_domain_mode: 'config',
			unifi_profiles: [
				{
					id: 'home',
					sync_owner: 'master',
					enabled: true,
					base_url: 'https://192.0.2.1',
					site_id: 'site-1',
					poll_interval: '90s',
					classic_clients: false,
					tls_pin_sha256:
						'sha256:abcdefghijklmnopqrstuvwxyz0123456789abcdef0123456789abcdef01',
					ca_file: null,
					insecure_skip_verify: false,
				},
			],
			unifi_bindings: { master: 'home', garage: 'home' },
		});
	});

	it('migrates legacy flat unifi into a default profile', () => {
		const form = formFromClients({
			local_domain: 'home.arpa',
			local_domain_mode: 'unifi_then_config',
			unifi: {
				enabled: true,
				base_url: 'https://192.0.2.1',
				site_id: '',
				poll_interval: '60s',
				classic_clients: true,
				tls_pin_sha256: null,
				ca_file: null,
				insecure_skip_verify: false,
			},
		});
		expect(form.profiles[0]).toMatchObject({
			id: 'default',
			enabled: true,
			base_url: 'https://192.0.2.1',
			sync_owner: 'local',
		});
	});

	it('clears pin and ca when switching to insecure', () => {
		const form: ClientsUnifiForm = {
			local_domain: 'home.arpa',
			local_domain_mode: 'unifi_then_config',
			selected_profile_id: 'default',
			bindings: {},
			profiles: [
				{
					id: 'default',
					enabled: true,
					base_url: 'https://192.0.2.1',
					site_id: '',
					poll_seconds: 60,
					classic_clients: true,
					tls: 'insecure',
					tls_pin_sha256: 'sha256:dead',
					ca_file: '/old.pem',
					sync_owner: 'local',
					api_key: '',
					has_api_key: false,
					clear_api_key: false,
				},
			],
		};

		expect(clientsPatchFromForm(form).unifi_profiles).toMatchObject([
			{
				tls_pin_sha256: null,
				ca_file: null,
				insecure_skip_verify: true,
			},
		]);
	});

	it('defaults when the clients section is empty', () => {
		expect(formFromClients(undefined).profiles[0]?.enabled).toBe(false);
		expect(formFromClients({}).local_domain).toBe('home.arpa');
	});
});
