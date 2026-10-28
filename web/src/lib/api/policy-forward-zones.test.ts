import { describe, expect, it } from 'vitest';
import { forwardZoneIdFromApex, parseForwardZones } from './policy';

describe('forwardZoneIdFromApex', () => {
	it('slugifies the apex', () => {
		expect(forwardZoneIdFromApex('spielab.de.')).toBe('spielab-de');
		expect(forwardZoneIdFromApex('Home.LAN')).toBe('home-lan');
	});
});

describe('parseForwardZones', () => {
	it('keeps zones that were saved with an empty id', () => {
		expect(
			parseForwardZones({
				resolver: {
					forward_zones: [
						{
							id: '',
							zone: 'spielab.de',
							targets: ['192.168.3.199'],
							validate: false,
						},
					],
				},
			}),
		).toEqual([
			{
				id: 'spielab-de',
				zone: 'spielab.de',
				targets: ['192.168.3.199'],
				validate: false,
			},
		]);
	});

	it('keeps an explicit id', () => {
		expect(
			parseForwardZones({
				resolver: {
					forward_zones: [
						{ id: 'lab', zone: 'lab.internal', targets: ['10.0.0.1'], validate: true },
					],
				},
			}),
		).toEqual([
			{ id: 'lab', zone: 'lab.internal', targets: ['10.0.0.1'], validate: true },
		]);
	});
});
