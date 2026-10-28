/** PWA theme-color / manifest colors aligned with tokens.css semantic values. */
export const PWA_THEME_COLOR = '#0060df';
export const PWA_BACKGROUND_LIGHT = '#f2f2f7';
export const PWA_BACKGROUND_DARK = '#000000';

export function themeColorFor(resolved: 'light' | 'dark'): string {
	return resolved === 'dark' ? PWA_BACKGROUND_DARK : PWA_THEME_COLOR;
}
