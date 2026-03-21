/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        base: '#ddd8be',
        contrast: '#233747',
        safe: '#2d7d46',
        critical: '#c94a3f',
        warning: '#e8943a',
        accent: '#f47a58',
        card: '#ece8d4',
        border: '#c4b896',
        muted: '#8b7355',
      },
      fontFamily: {
        display: ['Sora', 'sans-serif'],
        body: ['Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      maxWidth: {
        content: '1250px',
      },
    },
  },
  plugins: [],
};
