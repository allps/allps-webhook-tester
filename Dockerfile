FROM python:3.13.1-alpine

WORKDIR /app

RUN pip install --no-cache-dir fastapi 'uvicorn[standard]' loguru

COPY app.py .
COPY static/ ./static/

ENV WEBHOOK_TESTER_DATA=/data
VOLUME ["/data"]

EXPOSE 8095

CMD ["python", "app.py", "--host", "0.0.0.0", "--port", "8095"]



# USAGE EXAMPLE
# docker build -t webhook-tester .
#
# docker run -d --name webhook-tester \
#   -p 8000:8000 \
#   -e WEBHOOK_TESTER_USER=admin \
#   -e WEBHOOK_TESTER_PASSWORD=s3cret \
#   -v "$PWD/data:/data" \
#   webhook-tester
