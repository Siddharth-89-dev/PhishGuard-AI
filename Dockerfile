FROM python:3.11-slim

WORKDIR /app

# Prevent Python from writing .pyc files and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy requirements first for better layer caching
COPY requirements.txt .

# Install dependencies using pre-built binary wheels
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --prefer-binary -r requirements.txt

# Copy full application code (backend + frontend)
COPY . .

WORKDIR /app/backend

ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
