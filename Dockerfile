FROM base/archlinux:latest
MAINTAINER Thomas KILIAN

RUN pacman -Syu --noconfirm && \
    pacman -S --noconfirm make cmake git clang gcc pkg-config boost python

WORKDIR /root

ADD . /root/

CMD cd /root && touch build && rm -r build && mkdir -p build && cd build && cmake .. && make -j4 bttest
