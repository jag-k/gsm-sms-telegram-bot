ARG PYTHON_VERSION=3.13

FROM python:${PYTHON_VERSION}-alpine AS build

RUN --mount=type=cache,target=/root/.cache/pip \
    pip install uv

# Install build dependencies for opentelemetry like opentelemetry-instrumentation-system-metric
RUN --mount=type=cache,target=/root/.cache/apk \
    apk add gcc python3-dev musl-dev linux-headers

# Change the working directory to the `app` directory
WORKDIR /app

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --frozen --no-install-project --no-editable --compile-bytecode --no-dev --link-mode=copy


FROM python:${PYTHON_VERSION}-alpine

WORKDIR /app

# Copy the environment, but not the source code
COPY --from=build /app/.venv /app/.venv

COPY . /app
ENV PATH="/app/.venv/bin:$PATH"

ARG LOGFIRE__REVISION=main
ENV LOGFIRE__REVISION=LOGFIRE__REVISION

CMD ["python", "src/main.py"]
