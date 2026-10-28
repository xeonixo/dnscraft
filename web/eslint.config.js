import eslintPluginSvelte from 'eslint-plugin-svelte';
import tseslint from 'typescript-eslint';

export default tseslint.config(
	{ ignores: ['build/', '.svelte-kit/', 'node_modules/'] },
	...tseslint.configs.recommended,
	...eslintPluginSvelte.configs.recommended,
	...eslintPluginSvelte.configs.prettier,
	{
		files: ['**/*.svelte'],
		languageOptions: {
			parserOptions: { parser: tseslint.parser },
		},
	},
);
