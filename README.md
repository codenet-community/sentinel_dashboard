# Sentinel Dashboard

A modern cybersecurity dashboard for monitoring and analyzing threat data using Firebase.

## Features

- Real-time threat monitoring
- Interactive threat visualization
- CyberGuard AI-powered threat analysis
- CyberForge automated security solutions
- Blockchain-inspired analytics

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/sentinel_dashboard.git
cd sentinel_dashboard
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

## Deployment

The application is configured for easy deployment to platforms like Vercel, Netlify, or any static hosting service.

### Netlify Deployment

This project includes Netlify configuration in the `public/_redirects` file for proper SPA routing. To deploy to Netlify:

1. Push your code to a Git repository
2. Connect your repository to Netlify
3. Use the following build settings:
   - Build command: `npm run build`
   - Publish directory: `dist`

## Project Structure

- `/src/pages` - Main page components
- `/src/components` - Reusable UI components
- `/src/features` - Feature-specific components
- `/src/hooks` - Custom React hooks
- `/src/utils` - Utility functions

## Routes

The application has the following routes:

- `/` - Main dashboard
- `/cyber-guard` - AI-powered threat analysis
- `/cyber-forge` - Automated security solutions
- `/blockchain-analytics` - Blockchain-inspired analytics

## Technologies

- React
- TypeScript
- Vite
- Firebase Realtime Database
- React Router
- Recharts
- Framer Motion
- Tailwind CSS
- shadcn/ui
