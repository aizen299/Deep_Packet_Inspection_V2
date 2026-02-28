FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN pip install fastapi uvicorn scikit-learn joblib numpy

EXPOSE 5050

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "5050"]