FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UNKEV_DB=/data/unkev.db

RUN useradd --create-home --uid 10001 unkev \
 && mkdir /data && chown unkev:unkev /data

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt

# App code stays root-owned: the runtime user can read it, not modify it.
COPY . .

USER unkev
EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers"]
