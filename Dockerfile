FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for building python packages (if needed)
RUN apt-get update && apt-get install -y \
    gcc \
    default-libmysqlclient-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create uploads directory
RUN mkdir -p uploads/avatars uploads/posts uploads/messages

CMD ["uvicorn", "backend.backapi:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--timeout-keep-alive", "120", "--limit-concurrency", "2000", "--backlog", "4096"]