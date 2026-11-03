import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter({
      pages: 'build',
      assets: 'build',
      fallback: 'index.html'
    }),
    // The default is a build timestamp. A fixed name keeps web/build
    // reproducible so CI can check the committed copy against a fresh build.
    version: { name: 'kestrel' }
  }
};

export default config;
