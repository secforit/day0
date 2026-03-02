/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#ffffff',
        foreground: '#0a0a0a',
        card: '#fafafa',
        'card-foreground': '#0a0a0a',
        primary: '#dc2626',
        'primary-foreground': '#ffffff',
        muted: '#fafafa',
        'muted-foreground': '#525252',
        border: '#e5e5e5',
        input: '#e5e5e5',
        ring: '#dc2626',
        severity: {
          critical: '#dc2626',
          high: '#f97316',
          medium: '#eab308',
          low: '#22c55e',
        },
      },
      fontFamily: {
        sans: ['var(--font-space-grotesk)', 'Space Grotesk', 'sans-serif'],
        mono: ['var(--font-jetbrains-mono)', 'JetBrains Mono', 'monospace'],
      },
      borderRadius: {
        lg: '0.625rem',
        md: 'calc(0.625rem - 2px)',
        sm: 'calc(0.625rem - 4px)',
      },
    },
  },
  plugins: [],
}
