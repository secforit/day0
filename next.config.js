/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: {
      allowedOrigins: ['localhost:3000']
    }
  },
  async headers() {
    return [
      {
        source: '/rss',
        headers: [
          {
            key: 'Content-Type',
            value: 'application/rss+xml; charset=utf-8'
          },
          {
            key: 'Cache-Control',
            value: 'public, max-age=3600'
          }
        ]
      }
    ];
  }
};

module.exports = nextConfig;