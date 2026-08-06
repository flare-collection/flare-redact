# flare-redact gateway — a redaction sidecar in ~120 MB.
#
# Build from the repository root so the build context contains the sources:
#   docker build -f docker/Dockerfile -t flare-redact-gateway .
#
# The image ships only the compiled output and production dependencies, runs as
# an unprivileged user, and listens on 0.0.0.0 because a container's loopback is
# not reachable from its neighbours. Publish it to 127.0.0.1 on the host, or keep
# it on an internal network — see docker/README.md.

# ---- build ------------------------------------------------------------------
FROM node:22-alpine AS build
WORKDIR /src

# Dependencies first, so a source-only change does not reinstall the toolchain.
COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Reinstall without dev dependencies for the runtime layer.
RUN npm ci --omit=dev

# ---- runtime ----------------------------------------------------------------
FROM node:22-alpine AS runtime
ENV NODE_ENV=production \
    FLARE_GATEWAY_HOST=0.0.0.0 \
    FLARE_GATEWAY_PORT=8787

WORKDIR /app
COPY --from=build /src/node_modules ./node_modules
COPY --from=build /src/dist ./dist
COPY --from=build /src/package.json ./package.json
COPY bin/flare-gateway.mjs ./bin/flare-gateway.mjs

# node:alpine already provides an unprivileged `node` user.
USER node
EXPOSE 8787

# Liveness only — readiness is the same endpoint, since the gateway is ready as
# soon as it can accept a connection.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.FLARE_GATEWAY_PORT||8787)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["node", "bin/flare-gateway.mjs"]
