FROM python:trixie

WORKDIR /app

COPY requirements.txt ./
RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates
RUN pip install --no-cache-dir -r requirements.txt

COPY ./app /app

CMD ["python", "get_token.py"]
