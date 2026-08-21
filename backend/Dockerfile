# backend/Dockerfile

FROM node:20-bullseye

# Install build tools for C++
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install API deps first so this layer is cached across source-only changes.
COPY api/package.json api/package-lock.json ./api/
RUN cd api && npm ci --omit=dev

# Copy the rest of the backend and build the C++ engine.
COPY . .
RUN mkdir -p /app/output /app/api/uploads
RUN chmod +x build.sh && ./build.sh

# Drop privileges: the engine parses untrusted capture files, so it should not
# run as root. `node` (uid 1000) ships with the base image.
RUN chown -R node:node /app
USER node

EXPOSE 4000

WORKDIR /app/api
CMD ["node", "server.js"]
