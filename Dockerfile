FROM ghcr.io/praekeltfoundation/python-base-nw:3.10-bullseye

COPY sync.py /app

WORKDIR /app

RUN pip install -r requirements.txt

CMD /usr/local/bin/python -u sync.py
