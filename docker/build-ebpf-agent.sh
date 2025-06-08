#!/bin/bash

# --- 1. 进入项目根目录 (如果脚本不在根目录的话) ---
# 获取当前脚本的目录
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
# 假设你的项目根目录是脚本所在目录的上一级
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
SRC_DIR=${PROJECT_ROOT}/ebpf-agent
cd "$PROJECT_ROOT"
echo $SRC_DIR

echo "Current working directory: $PROJECT_ROOT"

# --- 2. 构建 Docker 镜像 ---
echo "Building Docker image..."
# 确保 Dockerfile 在 docker/ 目录下，并且构建上下文是项目根目录
docker build -f docker/Dockerfile.ebpf-agent -t ebpf-agent:v2 .

if [ $? -ne 0 ]; then
    echo "Error: Docker image build failed."
    exit 1
fi
echo "Docker image built successfully"
