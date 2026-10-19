FROM docker.io/library/archlinux:latest
LABEL maintainer="Thomas KILIAN"

RUN pacman -Syu --noconfirm --needed cmake gcc make pkgconf gmp libgcrypt openssl

WORKDIR /root/zklaim

COPY . .

RUN cmake -S . -B build && cmake --build build --parallel && cmake --install build

CMD ["cmake", "--build", "build", "--target", "bttest"]
