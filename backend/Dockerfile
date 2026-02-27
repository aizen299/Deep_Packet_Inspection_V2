# Use lightweight Linux base
FROM ubuntu:22.04

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt update && apt install -y \
    build-essential \
    cmake \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy backend source
COPY . .

# Build the engine
RUN mkdir build && cd build && cmake .. && make -j$(nproc)

# Default command
CMD ["./build/bin/dpi_engine", "data/sample.pcap"]