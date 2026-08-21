FROM python:3.11-slim

WORKDIR /app

# Dependency layer first, pinned via requirements.txt.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root: this service deserialises a model file and serves HTTP.
RUN useradd --create-home --uid 1000 mlsvc && chown -R mlsvc:mlsvc /app
USER mlsvc

EXPOSE 5050

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "5050"]
