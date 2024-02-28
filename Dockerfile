FROM python:3.12-alpine

WORKDIR /app

COPY requirements.txt requirements.txt

RUN pip install -r requirements.txt

COPY eaas.py eaas.py

ENTRYPOINT ["python", "eaas.py"]