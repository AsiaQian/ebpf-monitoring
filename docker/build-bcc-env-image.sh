#!/bin/bash

# --- 1. 进入项目根目录 (如果脚本不在根目录的话) ---
# 获取当前脚本的目录
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
# 假设你的项目根目录是脚本所在目录的上一级
PROJECT_ROOT=$(dirname "$SCRIPT_DIR")
#PROJECT_ROOT=$SCRIPT_DIR
cd "$PROJECT_ROOT"

echo "Current working directory: $(pwd)"



# --- 3. 构建 Docker 镜像 ---
echo "Building Docker image..."
# 确保 Dockerfile 在 docker/ 目录下，并且构建上下文是项目根目录
docker build -f docker/Dockerfile.bcc_env -t ubuntu-bcc-env:latest .

if [ $? -ne 0 ]; then
    echo "Error: Docker image build failed."
    exit 1
fi
echo "Docker image built successfully: ubuntu-bcc-env:latest"

# 提示可以运行eBPF demo应用
echo "🎉 Docker image built successfully!"
echo "To run your eBPF demo application, execute these commands in your terminal:"
echo ""
echo "    docker run -it --privileged -v /sys/kernel/tracing:/sys/kernel/tracing ubuntu-bcc-env:latest bash"
echo "    python3 /app/ebpf-hello-world/hello.py"
echo ""
echo "Enjoy your eBPF development!"