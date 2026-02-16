// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://infrashift.github.io',
	base: '/garmr',
	integrations: [
		starlight({
			title: 'Garmr',
			favicon: '/favicon.jpg',
			customCss: ['./src/styles/custom.css'],
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/infrashift/garmr',
				},
			],
			editLink: {
				baseUrl: 'https://github.com/infrashift/garmr/edit/main/docs/',
			},
			sidebar: [
				{
					label: 'Start Here',
					items: [
						{ label: 'Overview', slug: 'docs' },
						{ label: 'What is CUE?', slug: 'docs/what-is-cue' },
						{ label: 'Getting Started', slug: 'docs/getting-started' },
					],
				},
				{
					label: 'Guides',
					items: [
						{ label: 'CLI Reference', slug: 'docs/guides/cli' },
						{ label: 'REST API Reference', slug: 'docs/guides/rest-api' },
						{ label: 'Target & Namespace Filtering', slug: 'docs/guides/filtering' },
						{ label: 'CI/CD Pipeline Integration', slug: 'docs/guides/cicd' },
						{ label: 'Developer Experience', slug: 'docs/guides/developer-experience' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'Policy Schema', slug: 'docs/reference/policy-schema' },
						{ label: 'Policy Loading', slug: 'docs/reference/policy-loading' },
						{ label: 'Server Configuration', slug: 'docs/reference/configuration' },
					],
				},
				{
					label: 'Policy Library',
					collapsed: true,
					items: [
						{ label: 'Real-World Examples', slug: 'docs/policies/real-world' },
						{
							label: 'Other Examples',
							collapsed: true,
							autogenerate: { directory: 'docs/policies/generated' },
						},
					],
				},
				{
					label: 'Advanced',
					collapsed: true,
					items: [
						{ label: 'Plugin Architecture', slug: 'docs/advanced/plugins' },
						{ label: 'Storage Backends', slug: 'docs/advanced/storage-backends' },
						{ label: 'Concurrency Model', slug: 'docs/advanced/concurrency' },
					],
				},
				{
					label: 'Comparisons',
					collapsed: true,
					items: [
						{ label: 'Garmr vs OPA: Features', slug: 'docs/comparisons/opa-features' },
						{ label: 'Garmr vs OPA: Performance', slug: 'docs/comparisons/opa-performance' },
					],
				},
				{
					label: 'Project',
					collapsed: true,
					items: [
						{ label: 'Roadmap', slug: 'docs/project/roadmap' },
					],
				},
			],
		}),
	],
});
