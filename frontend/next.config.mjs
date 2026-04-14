/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    // Tell Next.js NOT to bundle better-sqlite3 — it must load as a native
    // Node.js require() at runtime. The build will still succeed even when
    // the .node binary isn't present locally; it will compile during
    // `npm install` on Hostinger.
    serverComponentsExternalPackages: ['better-sqlite3'],
  },
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
