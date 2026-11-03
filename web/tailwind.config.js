/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: '#090d16',
        surface: '#111726',
        border: '#1f293d',
        primary: {
          DEFAULT: '#3b82f6',
          hover: '#2563eb',
        },
        tier0: '#ef4444', // Red for critical tier-0
        tier1: '#f97316', // Orange
        tier2: '#eab308', // Yellow
        tier3: '#64748b', // Slate
      },
    },
  },
  plugins: [],
}
