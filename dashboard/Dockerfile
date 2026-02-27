# dashboard/Dockerfile

FROM node:20-alpine

WORKDIR /app

COPY . .

RUN npm install

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

EXPOSE 3000

CMD ["npm", "run", "start"]