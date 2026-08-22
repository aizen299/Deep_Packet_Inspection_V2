FROM python:3.11-slim

WORKDIR /app

# Dependency layer first, pinned via requirements.txt.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Train at build time rather than on the first request. The artifact is seeded
# and derived entirely from files already in this image, so building it here is
# identical to what the service would compute on its own -- it just moves ~10-30s
# of fitting off the cold-start path. On a suspending free-tier instance that
# delay lands on top of container wake-up and can exceed the caller's timeout,
# which surfaces as an unscored capture.
RUN python train_model.py

# Non-root: this service deserialises a model file and serves HTTP.
RUN useradd --create-home --uid 1000 mlsvc && chown -R mlsvc:mlsvc /app
USER mlsvc

EXPOSE 5050

# Shell form so a platform-assigned $PORT is honoured; compose leaves it unset.
CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT:-5050}"]
