FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /usr/src/app
COPY requirements.txt ./
RUN --mount=type=cache,target=/root/.cache \
    pip install -r requirements.txt

# RUN --mount=type=cache,target=/root/.cache \
#     pip install https://github.com/muchdogesec/file2txt/releases/download/main-2024-11-29-15-39-43/file2txt-0.0.1b2-py3-none-any.whl
# RUN --mount=type=cache,target=/root/.cache \
#         pip install https://github.com/muchdogesec/stix2arango/releases/download/main-2025-01-14-11-49-13/stix2arango-0.0.3-py3-none-any.whl
# COPY ./txt2detection-0.0.1-py3-none-any.whl .
# RUN pip install ./txt2detection-0.0.1-py3-none-any.whl 