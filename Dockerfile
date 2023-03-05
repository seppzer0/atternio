FROM python:3-slim

WORKDIR /atternio
RUN apt update && \ 
    apt install -y git && \
    python3 -m pip install tabulate && \
    # acquire CAPEC dictionary
    git clone --depth 1 https://github.com/mitre/cti && \
    mv cti/capec/2.1/attack-pattern ./attack-patterns && \
    rm -rf cti
COPY ./src ./app
ENTRYPOINT [ "python3", "app/app.py" ]