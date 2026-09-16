FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts
COPY src ./src
COPY app ./app
USER node
ENV PORT=3000
EXPOSE 3000
CMD ["node", "app/server.js"]
