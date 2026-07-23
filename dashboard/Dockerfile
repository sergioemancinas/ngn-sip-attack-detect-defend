# syntax=docker/dockerfile:1.7

FROM node:22.12.0-alpine3.20@sha256:027911463b296bdaf6df82b5ccf2c6b290fee725d5fba6513a037ed019400625 AS deps
WORKDIR /app
RUN apk add --no-cache libc6-compat
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts

FROM node:22.12.0-alpine3.20@sha256:027911463b296bdaf6df82b5ccf2c6b290fee725d5fba6513a037ed019400625 AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
# NEXT_PUBLIC_* vars are inlined into the client bundle at build time, not read
# at runtime, so the Grafana origin used by the embedded panels must be a build arg.
ARG NEXT_PUBLIC_GRAFANA_URL=""
ENV NEXT_PUBLIC_GRAFANA_URL=$NEXT_PUBLIC_GRAFANA_URL
RUN npm run build

FROM node:22.12.0-alpine3.20@sha256:027911463b296bdaf6df82b5ccf2c6b290fee725d5fba6513a037ed019400625 AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs \
  && adduser --system --uid 1001 --ingroup nodejs nextjs

COPY --from=builder /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

USER nextjs
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
