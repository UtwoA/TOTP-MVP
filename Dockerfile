FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY radius ./radius

RUN pip install --no-cache-dir .

EXPOSE 1812/udp

CMD ["radius-totp", "serve"]
