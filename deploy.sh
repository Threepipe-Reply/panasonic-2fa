#!/bin/bash

# Build and push to Docker Hub
docker build -t your-username/panasonic-2fa .
docker push your-username/panasonic-2fa

# Deploy to Lightsail
echo "Run this on your Lightsail instance:"
echo "docker pull your-username/panasonic-2fa"
echo "docker run -d -p 80:5000 --name panasonic-2fa your-username/panasonic-2fa"