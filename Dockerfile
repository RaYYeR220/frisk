# Frisk ASP — container for Cloud Run / any container host.
FROM node:20-slim AS build
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app

# Install with a warm cache: manifests first.
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY packages/shared/package.json ./packages/shared/
COPY packages/engine/package.json ./packages/engine/
COPY packages/asp/package.json ./packages/asp/
COPY packages/guard/package.json ./packages/guard/
RUN pnpm install --frozen-lockfile

# Build the ASP (bundles @frisk/* into dist/).
COPY packages ./packages
COPY tsconfig.base.json ./
RUN pnpm --filter @frisk/asp build

# --- runtime ---
FROM node:20-slim AS run
ENV NODE_ENV=production PORT=8080
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/asp/node_modules ./packages/asp/node_modules
COPY --from=build /app/packages/asp/dist ./packages/asp/dist
COPY --from=build /app/packages/asp/package.json ./packages/asp/
EXPOSE 8080
CMD ["node", "packages/asp/dist/main.js"]
