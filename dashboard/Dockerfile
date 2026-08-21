# dashboard/Dockerfile

# ---- Build stage ------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Dependency layer first so source edits do not invalidate npm install.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# NEXT_PUBLIC_* values are inlined into the client bundle at build time, so the
# API URL has to be supplied here -- setting it at runtime has no effect.
ARG NEXT_PUBLIC_API_URL=http://localhost:4000
ARG NEXT_PUBLIC_API_KEY=""
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_API_KEY=$NEXT_PUBLIC_API_KEY
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# ---- Runtime stage ----------------------------------------------------------
FROM node:20-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Production dependencies only -- no build tooling in the final image.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/next.config.ts ./

USER node

EXPOSE 3000

CMD ["npm", "run", "start"]
