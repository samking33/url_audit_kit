/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    // Keep the WASM SQLite runtime external so the server bundle can load it
    // directly from node_modules at runtime.
    serverComponentsExternalPackages: ['node-sqlite3-wasm'],
  },
  typescript: {
    ignoreBuildErrors: true,
  },
};

export default nextConfig;
