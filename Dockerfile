# Python base image
FROM python:3.11.4

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app


# Install dependencies
RUN apt-get update \
  && apt-get install -y curl \
  && curl -sSL https://install.python-poetry.org | python -

# Make sure scripts in .local are usable:
ENV PATH=/root/.local/bin:$PATH

# Copy only requirements to cache them in docker layer
COPY poetry.lock pyproject.toml ./

# Project initialization:
RUN poetry config virtualenvs.create false \
  && poetry install --no-interaction --no-ansi

# Copying the project files into the container
COPY . .
  



