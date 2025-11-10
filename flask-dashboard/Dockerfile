# flask-dashboard/Dockerfile (production-ready)
FROM python:3.11-slim

# create non-root user for security
ENV APP_HOME=/app
WORKDIR $APP_HOME

# install system deps needed for mysql-connector / bcrypt build if any (kept minimal)
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential gcc libffi-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# install python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# copy application code
COPY . .

# ensure files are readable and not owned by root in ways that break runtime (optional)
RUN groupadd -r app && useradd -r -g app app && chown -R app:app $APP_HOME
USER app

ENV FLASK_ENV=production
EXPOSE 5000

# Use gunicorn as the WSGI server
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app", "--workers", "3", "--timeout", "120"]

