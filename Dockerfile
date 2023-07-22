FROM python:3.11-alpine3.18 as base

ADD atternio /opt/atternio
ADD pyproject.toml /opt
ADD poetry.lock /opt
ADD README.md /opt/README.md
ENV PYTHONPATH /opt
WORKDIR /opt

RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install poetry twine && \
    python3 -m poetry config virtualenvs.create false && \
    python3 -m poetry install --no-root

CMD [ "/bin/sh" ]
