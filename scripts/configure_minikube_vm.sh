#!/bin/bash

echo "🚀 开始为 Minikube VM 配置阿里云镜像源并安装内核头文件..."
echo "--------------------------------------------------------"

# 确保 Minikube 正在运行
if ! minikube status &> /dev/null; then
    echo "Minikube 未运行，请先启动 Minikube。"
    exit 1
fi

# 使用 minikube ssh 在 VM 内部执行所有命令
# 注意：多行命令和变量需要正确转义，以确保它们在 VM 内部被解释
minikube ssh "
    echo \"--- 备份 sources.list ---\" && \
    sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak && \

    echo \"--- 尝试获取 Minikube VM 版本代号 ---\" && \

    # 尝试多种方式获取 RELEASE_NAME
    # 1. 尝试 lsb_release (可能缺失)
    RELEASE_NAME=\$(lsb_release -cs 2>/dev/null)

    if [ -z \"\$RELEASE_NAME\" ]; then
        # 2. 尝试从 /etc/os-release 中获取 VERSION_CODENAME
        RELEASE_NAME=\$(grep VERSION_CODENAME /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')
    fi

    if [ -z \"\$RELEASE_NAME\" ]; then
        # 3. 尝试从 /etc/os-release 中获取 VERSION_ID 并根据常见版本猜测代号
        VERSION_ID=\$(grep VERSION_ID /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '\"')
        case \"\$VERSION_ID\" in
            \"9\") RELEASE_NAME=\"stretch\" ;; # Debian 9
            \"10\") RELEASE_NAME=\"buster\" ;; # Debian 10
            \"11\") RELEASE_NAME=\"bullseye\" ;; # Debian 11
            \"12\") RELEASE_NAME=\"bookworm\" ;; # Debian 12
            \"18.04\") RELEASE_NAME=\"bionic\" ;; # Ubuntu 18.04
            \"20.04\") RELEASE_NAME=\"focal\" ;; # Ubuntu 20.04
            \"22.04\") RELEASE_NAME=\"jammy\" ;; # Ubuntu 22.04
            *) RELEASE_NAME=\"\" ;; # 无法识别的版本
        esac
    fi

    if [ -z \"\$RELEASE_NAME\" ]; then
        echo \"⚠️ 错误：无法自动获取操作系统版本代号。\"
        echo \"   请手动检查 Minikube VM 内的 /etc/os-release 文件，并根据其内容确定正确的版本代号。\"
        echo \"   通常，Minikube 基于 Debian 或 Ubuntu。例如，如果看到 VERSION=\\\"11 (bullseye)\\\" 或 VERSION_CODENAME=bullseye，则代号是 'bullseye'。\"
        echo \"   /etc/os-release 内容如下：\"
        cat /etc/os-release
        exit 1 # 无法自动确定，脚本退出
    fi
    echo \"当前 Minikube VM 的 Ubuntu/Debian 版本代号是: \${RELEASE_NAME}\" && \

    echo \"--- 配置阿里云镜像源 ---\" && \
    sudo bash -c \"cat > /etc/apt/sources.list <<\\EOF
deb http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME} main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME}-updates main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME}-backports main restricted universe multiverse
deb http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME}-security main restricted universe multiverse

deb-src http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME} main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME}-updates main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME}-backports main restricted universe multiverse
deb-src http://mirrors.aliyun.com/ubuntu/ \${RELEASE_NAME}-security main restricted universe multiverse
EOF\" && \

    echo \"--- 更新 apt 包索引 ---\" && \
    sudo apt update && \

    echo \"--- 安装 linux-headers-$(uname -r) ---\" && \
    sudo apt install -y linux-headers-\$(uname -r) && \

    echo \"--- 内核头文件安装完成 ---\" && \
    echo \"--- 验证 /lib/modules/\$(uname -r)/build 链接 ---\" && \
    ls -l /lib/modules/\$(uname -r)/build && \
    echo \"--- 验证 /usr/src/linux-headers/\$(uname -r)/include/linux/version.h 文件 ---\" && \
    ls /usr/src/linux-headers-\$(uname -r)/include/linux/version.h
"

echo "--------------------------------------------------------"
echo "✅ Minikube VM 配置阿里云镜像源和安装内核头文件已完成。"
echo "如果上面命令没有报错，现在可以尝试重新部署 eBPF Agent DaemonSet 了。"
echo "记得先重新构建 Docker 镜像，然后应用 DaemonSet。"