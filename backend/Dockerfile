# backend/Dockerfile

FROM node:20-bullseye

# Install build tools for C++
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy backend
COPY . .

# Build C++ engine
RUN chmod +x build.sh && ./build.sh

# Install API deps
WORKDIR /app/api
RUN npm install

EXPOSE 4000

CMD ["node", "server.js"]