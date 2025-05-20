FROM python:3.11-slim

# Install system dependencies including Nmap
RUN apt-get update && apt-get install -y \
    git \
    nmap && \  # <-- Added Nmap installation
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap

WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Environment variables
ENV FLASK_APP=wsgi.py
ENV FLASK_ENV=production

# Start Flask using Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "wsgi:app"]
