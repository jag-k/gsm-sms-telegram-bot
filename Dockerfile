ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-alpine as build

COPY --from=ghcr.io/astral-sh/uv:alpine /uv /bin/

# Change the working directory to the `app` directory
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-editable --compile-bytecode


#FROM python:${PYTHON_VERSION}-alpine
FROM alpine:latest

WORKDIR /app

# Copy the environment, but not the source code
COPY --from=build /app/.venv /app/.venv

COPY . /app
ENV PATH="/app/.venv/bin:$PATH"

CMD ["python", "src/main.py"]
