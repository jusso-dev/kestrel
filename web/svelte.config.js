import adapter from '@sveltejs/adapter-static';
import { readFileSync } from 'node:fs';

// The default version is a build timestamp. The workspace version keeps
// web/build reproducible, so CI can check the committed copy against a fresh
// build, and still changes with every release so open tabs pick it up.
const cargo = readFileSync(new URL('../Cargo.toml', import.meta.url), 'utf8');
const version = cargo.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (!version) throw new Error('workspace version not found in Cargo.toml');

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter({
      pages: 'build',
      assets: 'build',
      fallback: 'index.html'
    }),
    version: { name: `kestrel-${version}` }
  }
};

export default config;
