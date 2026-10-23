FROM node:22-bookworm-slim AS web
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
COPY companion/ /app/companion/
RUN npm run build && npm run build:companion

FROM python:3.12-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 DATA_DIR=/tmp/sentinelops
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/ ./backend/
COPY companion/ ./companion/
COPY deploy/ ./deploy/
COPY run.py ./
COPY --from=web /app/frontend/dist ./frontend/dist
COPY --from=web /app/companion/extension/dist ./companion/extension/dist
RUN python companion/package_extension.py && useradd --system --uid 10001 sentinelops
USER 10001
EXPOSE 8110
CMD ["sh", "-c", "exec uvicorn backend.app:create_app --factory --host 0.0.0.0 --port ${PORT:-8110} --workers 1 --no-access-log"]
