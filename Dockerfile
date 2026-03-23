# syntax=docker/dockerfile:1
FROM node:20-alpine AS base

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci --omit=dev && \
    npm rebuild better-sqlite3 && \
    npm cache clean --force
# Copy source code
COPY . .

# Security: non-root user
RUN addgroup -g 1001 nodejs && \
    adduser -S nodeuser -u 1001 -G nodejs && \
    chown -R nodeuser:nodejs /app

USER nodeuser

EXPOSE 3210 3737 3738

# Default command — override in docker run or compose
CMD ["node", "admin-server.js"]