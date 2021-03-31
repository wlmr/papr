FROM python:3.9

ENV PYTHONUNBUFFERED 1

RUN pip3 install --user petlib pytest flake8 autopep8 rope

ENV PATH="/root/.local/bin:$PATH"

ENV PYTHONPATH=/workspace/
