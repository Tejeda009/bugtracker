FROM node:20-bookworm

ENV PLAYWRIGHT_BROWSERS_PATH=/app/.playwright

RUN apt-get update && apt-get install -y \
    libnss3 libatk-bridge2.0-0 libdrm2 libxkbcommon0 libgbm1 \
    libasound2 libatspi2.0-0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libpango-1.0-0 libcairo2 fonts-liberation curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json* ./
RUN npm install
RUN npx playwright install --with-deps chromium

COPY . .

RUN addgroup --gid 1001 ctf && adduser --uid 1001 --gid 1001 --disabled-password ctf
RUN chown -R ctf:ctf /app
USER ctf

EXPOSE 3000
CMD ["node", "index.js"]
