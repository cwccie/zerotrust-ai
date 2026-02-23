FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
COPY sample_data/ sample_data/

RUN pip install --no-cache-dir .

EXPOSE 5000 8080

ENV ZEROTRUST_HOST=0.0.0.0
ENV ZEROTRUST_PORT=5000

CMD ["zerotrust-ai", "dashboard", "--host", "0.0.0.0", "--port", "5000"]
