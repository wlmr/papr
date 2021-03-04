FROM python:3.9

ENV PYTHONUNBUFFERED 1

RUN pip3 install --user petlib pytest flake8 autopep8 rope pyre-check

ENV PATH="/root/.local/bin:$PATH"

ENV PYTHONPATH=/workspace/

# Type checking pyre
#RUN wget https://github.com/facebook/watchman/releases/download/v2021.03.01.00/watchman-v2021.03.01.00-linux.zip && \
#    unzip watchman-*-linux.zip && \
#    mkdir -p /usr/local/{bin,lib} /usr/local/var/run/watchman && \
#    cp watchman-*-linux/bin/* /usr/local/bin && \
#    cp watchman-*-linux/lib/* /usr/local/lib && \
#    chmod 755 /usr/local/bin/watchman && \
#    chmod 2777 /usr/local/var/run/watchman && \
#    rm watchman-*-linux.zip && \
#    rm -r watchman-*-linux/
