# syntax=docker/dockerfile:1

FROM python:3.11-slim-buster

# Install git
RUN apt-get update && \
    apt-get install -y git && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy the requirements file
COPY requirements.txt requirements.txt

# Provide a GitHub Token as a build argument for private repos
ARG GITHUB_TOKEN
# Echo the GitHub Token (for debugging purposes only)
RUN echo "GITHUB_TOKEN is set to: $GITHUB_TOKEN"

# Configure Git to use the provided token
RUN echo "machine github.com login $GITHUB_TOKEN" > ~/.netrc && \
    git config --global url."https://".insteadOf git://

# Install Python dependencies
RUN pip3 install -r requirements.txt

# Copy the application files
COPY *.py /app

# Set the command to run the app
CMD [ "python3", "/app/server.py"]
