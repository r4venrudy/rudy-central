FROM node:24-bookworm-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run check

FROM node:24-bookworm-slim
ENV NODE_ENV=production PORT=4173 RUDY_DATA_DIR=/app/.data
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && mkdir -p /app/.data && chown -R node:node /app
COPY --from=build --chown=node:node /app/dist ./dist
COPY --from=build --chown=node:node /app/server ./server
COPY --from=build --chown=node:node /app/sensors ./sensors
USER node
EXPOSE 4173
CMD ["node", "server/index.mjs"]
