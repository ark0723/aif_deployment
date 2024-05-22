# Use Python 3.11 base image (Alpine version)
FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Install system dependencies
RUN apk update && \
    apk add --no-cache --virtual .build-deps gcc musl-dev postgresql-dev

# Set work directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip && \
    pip install -r /tmp/requirements.txt && \
    rm -rf /tmp

# Copy FastAPI application files
COPY ./app /app

# Expose port (FastAPI server)
EXPOSE 8001

# Command to run FastAPI server
CMD ["gunicorn", "main:app", "-b", "0.0.0.0:8001", "--worker-class", "uvicorn.workers.UvicornWorker", "--timeout", "120", "--reload", "--log-level", "info"]


