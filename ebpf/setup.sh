sudo apt-get update && \
    sudo apt-get install -y build-essential git cmake \
    zlib1g-dev libevent-dev \
    libelf-dev llvm libbpf-dev \
    clang libc6-dev \
    wget gcc-multilib linux-headers-generic

wget https://go.dev/dl/go1.24.1.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz