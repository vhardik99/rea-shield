FROM node:22-alpine
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY bin ./bin
COPY src ./src
COPY fixtures ./fixtures
USER node
ENTRYPOINT ["node", "/app/bin/rea-shield.mjs"]
