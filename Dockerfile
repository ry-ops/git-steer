# Git-Steer - GitHub Autonomy Engine MCP Server
# Multi-stage build for minimal production image

FROM node:22-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install all dependencies (including dev for build)
RUN npm ci

# Copy source code
COPY tsconfig.json ./
COPY src/ ./src/
COPY bin/ ./bin/

# Build TypeScript
RUN npm run build

# Production stage
FROM node:22-alpine

LABEL org.opencontainers.image.title="Git-Steer"
LABEL org.opencontainers.image.description="Self-hosting GitHub autonomy engine - MCP server for repo management"
LABEL org.opencontainers.image.source="https://github.com/ry-ops/git-steer"
LABEL org.opencontainers.image.licenses="MIT"

# Create non-root user
RUN addgroup -g 1001 -S gitsteer && \
    adduser -u 1001 -S gitsteer -G gitsteer

WORKDIR /app

# Copy package files and install production deps only
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Copy built files from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/bin ./bin

# Create config directory
RUN mkdir -p /home/gitsteer/.config/git-steer && \
    chown -R gitsteer:gitsteer /home/gitsteer

# Switch to non-root user
USER gitsteer

# Environment
ENV NODE_ENV=production

# The MCP server runs on stdio, no ports needed
# For status/health checks, use the CLI

ENTRYPOINT ["node", "bin/cli.js"]
CMD ["start", "--stdio"]
