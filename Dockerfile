FROM debian:latest
WORKDIR /atternio
RUN rm -rf .git* && \
    apt update && \ 
    apt full-upgrade -y && \
    apt install -y \
            python3 \
            python3-pip \
            git \
    && \
    python3 -m pip install tabulate && \
    # CAPEC dictionary
    git clone --depth 1 https://github.com/mitre/cti && \
    mv cti/capec/2.1/attack-pattern ./attack-patterns && \
    rm -rf cti
COPY ./src ./app
ENTRYPOINT [ "python3", "app/app.py" ]