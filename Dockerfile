FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y git && \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap
COPY . .

ENV FLASK_APP=wsgi.py
ENV FLASK_ENV=production

CMD ["gunicorn", "--bind", "0.0.0.0:8000", "wsgi:app"]
