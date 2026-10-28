// Line icons copied from docs/design/web-ui-prototype.html (stroke-based, 24x24 grid).
// Owned by the project: no icon dependency. Shapes are data, rendered by Icon.svelte.

type Tag = 'path' | 'rect' | 'circle' | 'line' | 'polyline' | 'polygon';

export interface IconShape {
	tag: Tag;
	attrs: Record<string, string | number>;
}

const path = (d: string): IconShape => ({ tag: 'path', attrs: { d } });
const rect = (x: number, y: number, width: number, height: number, rx: number): IconShape => ({
	tag: 'rect',
	attrs: { x, y, width, height, rx },
});
const circle = (cx: number, cy: number, r: number): IconShape => ({
	tag: 'circle',
	attrs: { cx, cy, r },
});
const line = (x1: number, y1: number, x2: number, y2: number): IconShape => ({
	tag: 'line',
	attrs: { x1, y1, x2, y2 },
});
const polyline = (points: string): IconShape => ({ tag: 'polyline', attrs: { points } });
const polygon = (points: string): IconShape => ({ tag: 'polygon', attrs: { points } });

export const ICON_SHAPES = {
	'alert-triangle': [
		path('M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z'),
		line(12, 9, 12, 13),
		line(12, 17, 12.01, 17),
	],
	ban: [circle(12, 12, 9), line(5.5, 5.5, 18.5, 18.5)],
	bell: [path('M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9'), path('M13.7 21a2 2 0 0 1-3.4 0')],
	'check-circle': [circle(12, 12, 9), polyline('8 12 11 15 16 9')],
	'chevron-right': [polyline('9 6 15 12 9 18')],
	download: [
		path('M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4'),
		polyline('7 10 12 15 17 10'),
		line(12, 15, 12, 3),
	],
	globe: [circle(12, 12, 9), path('M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18')],
	grid: [rect(3, 3, 7, 9, 2), rect(14, 3, 7, 5, 2), rect(14, 12, 7, 9, 2), rect(3, 16, 7, 5, 2)],
	'help-circle': [
		circle(12, 12, 9),
		path('M9.1 9a3 3 0 0 1 5.8 1c0 2-3 2.5-3 4'),
		line(12, 17, 12.01, 17),
	],
	info: [circle(12, 12, 9), line(12, 16, 12, 12), line(12, 8, 12.01, 8)],
	layers: [
		polygon('12 2 2 7 12 12 22 7 12 2'),
		polyline('2 17 12 22 22 17'),
		polyline('2 12 12 17 22 12'),
	],
	list: [
		path('M8 6h13M8 12h13M8 18h13'),
		line(3, 6, 3.01, 6),
		line(3, 12, 3.01, 12),
		line(3, 18, 3.01, 18),
	],
	lock: [rect(3, 11, 18, 11, 2), path('M7 11V7a5 5 0 0 1 10 0v4')],
	menu: [line(3, 6, 21, 6), line(3, 12, 21, 12), line(3, 18, 21, 18)],
	moon: [path('M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z')],
	network: [
		path('M2 12h20M6 12v6M18 12v6M12 12v6'),
		circle(4, 4, 2),
		circle(20, 4, 2),
		circle(12, 4, 2),
	],
	'message-square': [path('M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z')],
	'play-circle': [circle(12, 12, 9), polygon('10 8 16 12 10 16 10 8')],
	server: [rect(2, 2, 20, 8, 2), rect(2, 14, 20, 8, 2), line(6, 6, 6.01, 6), line(6, 18, 6.01, 18)],
	settings: [
		circle(12, 12, 3),
		path(
			'M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33h.01a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51h.01a1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82v.01a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z',
		),
	],
	sliders: [
		line(4, 21, 4, 14),
		line(4, 10, 4, 3),
		line(12, 21, 12, 12),
		line(12, 8, 12, 3),
		line(20, 21, 20, 16),
		line(20, 12, 20, 3),
		line(1, 14, 7, 14),
		line(9, 8, 15, 8),
		line(17, 16, 23, 16),
	],
	sun: [
		circle(12, 12, 4),
		path(
			'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
		),
	],
	target: [circle(12, 12, 9), circle(12, 12, 5), circle(12, 12, 1)],
	text: [path('M4 6h16M4 12h16M4 18h10')],
	user: [path('M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2'), circle(12, 7, 4)],
	'user-check': [
		path('M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'),
		circle(9, 7, 4),
		polyline('16 11 18 13 22 9'),
	],
	'x-circle': [circle(12, 12, 9), line(15, 9, 9, 15), line(9, 9, 15, 15)],
	x: [line(18, 6, 6, 18), line(6, 6, 18, 18)],
	zap: [path('M13 2 3 14h9l-1 8 10-12h-9l1-8z')],
	'arrow-right': [path('M5 12h14'), polyline('13 6 19 12 13 18')],
} satisfies Record<string, IconShape[]>;

export type IconName = keyof typeof ICON_SHAPES;

/** Semantic tone of a status; always paired with an icon and a word. */
export type StatusTone = 'ok' | 'warn' | 'danger' | 'neutral';
