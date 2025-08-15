# Stage 1: Build gobuster and ffuf using a Go builder image
FROM golang:1.20-alpine AS builder
WORKDIR /build

# Install git for cloning repositories
RUN apk add --no-cache git

# Build gobuster
RUN git clone https://github.com/OJ/gobuster.git && \
    cd gobuster && \
    git checkout v3.5.0 && \
    go build -o gobuster .

# Build ffuf
RUN git clone --depth 1 https://github.com/ffuf/ffuf.git && \
    cd ffuf && \
    go build -o ffuf .

# Stage 2: Final image based on Python slim
FROM python:3.10-slim
WORKDIR /app

COPY .env .

# Copy your application code
COPY . /app


# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install system dependencies required by sqlmap and runtime tools
RUN apt-get update && \
    apt-get install -y git nmap && \
    apt-get clean

# Install sqlmap directly from its official GitHub repository
# Install sqlmap directly from its official GitHub repository
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    rm -f /usr/local/bin/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    chmod +x /usr/local/bin/sqlmap


# Copy gobuster and ffuf binaries from the builder stage
COPY --from=builder /build/gobuster/gobuster /usr/local/bin/gobuster
COPY --from=builder /build/ffuf/ffuf /usr/local/bin/ffuf
RUN chmod +x /usr/local/bin/gobuster /usr/local/bin/ffuf

# Expose the port your app uses
EXPOSE 8501

# Run your Streamlit app when the container launches
CMD ["python", "main.py", "--streamlit"]
