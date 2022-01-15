FROM python:3.7

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

COPY derive.py setup_server.py validate_ecc.py virtual_card.py /app/
COPY ntag /app/ntag
COPY config.docker.py /app/config.py

USER nobody:nogroup
WORKDIR /app
CMD ["python3", "-u", "setup_server.py"]
