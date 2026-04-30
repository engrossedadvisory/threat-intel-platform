/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        navy: {
          950: '#050810',
          900: '#060c1a',
          800: '#080e1c',
          700: '#0a1428',
          600: '#0c1628',
          500: '#0f2040',
          400: '#142038',
          300: '#1e3a5f',
          200: '#2a5080',
          100: '#3d5a80',
        },
        sky: {
          400: '#38bdf8',
        },
        violet: {
          400: '#a78bfa',
        },
        rose: {
          500: '#ff4d6d',
        },
        slate: {
          300: '#c8d8f0',
          400: '#8fb0d0',
          500: '#5a7a9a',
          600: '#3d5a80',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
      },
    },
  },
  plugins: [],
}
