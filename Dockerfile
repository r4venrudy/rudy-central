FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run check

FROM node:24-bookworm-slim
ARG VCS_REF=unknown
LABEL org.opencontainers.image.source="https://github.com/r4venrudy/rudy-central" \
      org.opencontainers.image.description="Rudy Central web interface and API. The Linux kernel agent is distributed separately." \
      org.opencontainers.image.revision="${VCS_REF}"
ENV NODE_ENV=production PORT=4173 RUDY_DATA_DIR=/app/.data
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && mkdir -p /app/.data && chown -R node:node /app
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/server ./server
COPY --from=build --chown=node:node /app/sensors ./sensors
COPY --from=build --chown=node:node /app/scripts/evidence-convert.mjs ./scripts/evidence-convert.mjs
USER node
EXPOSE 4173
CMD ["node", "server/index.mts"]
