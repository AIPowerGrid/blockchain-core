# syntax = edrevo/dockerfile-plus

FROM ubuntu:focal

INCLUDE+ ci/Dockerfile

# The inherited Dockerfile switches to non-privileged context and we've
# just started configuring this image, give us root access
USER root

# Make development environment more standalone
RUN apt-get update && \
    apt-get install $APT_ARGS \
    apt-cacher-ng \
    gdb \
    gpg \
    lsb-release \
    nano \
    openssh-client \
    screen \
    sudo \
    zsh \
    && \
    rm -rf /var/lib/apt/lists/*

# Discourage root access, this is an interactive instance
#
# Sometimes these commands are run repetitively _after_ the non-sudo
# user was introduced and therefore these commands would fail
# To mitigate the build halting, you can add "|| true" so that it
# unconditionally returns 0
#
RUN groupadd docker && \
    usermod -aG sudo dash && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

# Disable noninteractive mode
ENV DEBIAN_FRONTEND="dialog"

# Expose Dash P2P and RPC ports for main network and test networks
EXPOSE 9788 8865 19788 18865

# We're done, switch back to non-privileged user
USER dash
