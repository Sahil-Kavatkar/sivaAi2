import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: 'dist', // Ensure the build output goes to the correct folder
  },
  server: {
    port: 5173, // Only required if you are working locally and need to specify a port
    host: true, // Expose server to the network (useful in local dev to access from other devices)
  },
});