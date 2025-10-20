###########################
# Builder stage
###########################
FROM rockylinux:9 AS builder

RUN set -eux \
    && dnf -y update \
    && dnf -y install dnf-plugins-core \
    && dnf config-manager --set-enabled crb \
    && dnf -y install \
        python3 \
        python3-pip \
        python3-devel \
        gcc \
        make \
        libvirt-client \
        libvirt-devel \
        libvirt-libs \
        libxml2-devel \
        pkgconfig \
        openssh-clients \
    && dnf -y clean all \
    && rm -rf /var/cache/dnf/*

WORKDIR /opt/virt-app

COPY requirements.txt ./requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

###########################
# Development runtime
###########################
FROM rockylinux:9 AS dev

RUN set -eux

RUN dnf -y update && \
    dnf -y install epel-release dnf-plugins-core && \
    dnf config-manager --set-enabled crb && \
    dnf -y install \ 
        vim-enhanced less \
        tree which file ripgrep \
        wget rsync \
        tar zip unzip \
        iproute iputils bind-utils traceroute \
        nmap-ncat tcpdump socat \
        procps-ng psmisc lsof strace gdb \
        bash-completion \
        jq yq \
        python3 python3-pip python3-devel \
        libvirt-client python3-libvirt \
        libvirt-devel libvirt-libs \
        libxml2-devel gcc make pkgconfig \
        openssh-clients \ 
        man-db man-pages \
      && dnf -y clean all \
      && rm -rf /var/cache/dnf/*

RUN useradd -m -u 1000 virt

USER virt
ENV PATH="/home/virt/.local/bin:$PATH"
WORKDIR /opt/virt-app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

COPY virt-app ./app
COPY config.yaml ./config.yaml
COPY alembic.ini ./alembic.ini
COPY bin ./bin

ENV PYTHONUNBUFFERED=1 \
    CONFIG_FILE=/opt/virt-app/config.yaml \
    LOG_LEVEL=INFO

EXPOSE 8000

ENTRYPOINT ["/opt/virt-app/bin/prestart.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

###########################
# Production runtime
###########################
FROM rockylinux:9-minimal AS prod

LABEL maintainer="Brandon Foos <webmaster@foos.net>"
LABEL description="FastAPI controller for managing libvirt hosts over SSH on Rocky Linux 9"

RUN set -eux \
    && microdnf -y update \
    && microdnf -y install --enablerepo=crb \
        python3 \
        libvirt-client \
        libvirt-libs \
        openssh-clients \
        shadow-utils \
    && microdnf -y clean all \
    && rm -rf /var/cache/dnf/*

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    CONFIG_FILE=/opt/virt-app/config.yaml \
    LOG_LEVEL=INFO

RUN useradd -m -u 1000 virt

WORKDIR /opt/virt-app
COPY virt-app ./app
COPY config.yaml ./config.yaml
COPY alembic.ini ./alembic.ini
COPY bin ./bin

RUN chown -R virt:virt /opt/virt-app

USER virt
EXPOSE 8000

ENTRYPOINT ["/opt/virt-app/bin/prestart.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
