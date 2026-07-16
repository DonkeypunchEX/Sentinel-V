FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY src ./src
RUN npm run build

FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY server.js db.js seed.json ./
COPY public ./public
COPY --from=build /app/public/app.js ./public/app.js
RUN mkdir -p /data && chown node:node /data
ENV WHSE_DATA_DIR=/data
VOLUME /data
EXPOSE 8080
USER node
CMD ["node", "server.js"]
