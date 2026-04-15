FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

COPY src/ src/
RUN npx tsc

# Production stage
FROM node:22-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist/ dist/

# Trust store is mounted or bundled at /app/trust-store
# Default: expects attestto-trust/countries/ at this path
ENV TRUST_STORE_PATH=/app/trust-store/countries
ENV PORT=8080

EXPOSE 8080

CMD ["node", "dist/server.js"]
