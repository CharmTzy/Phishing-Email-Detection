FROM python:3.11-slim

RUN apt-get update && apt-get install -y bash && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1000 user

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    HF_HOME=/home/user/.cache/huggingface \
    XDG_CACHE_HOME=/home/user/.cache \
    TLDEXTRACT_CACHE=/home/user/.cache/tldextract \
    PORT=7860 \
    STREAMLIT_SERVER_PORT=7860 \
    STREAMLIT_SERVER_ADDRESS=0.0.0.0 \
    BACKEND_HOST=0.0.0.0 \
    BACKEND_PORT=5000 \
    BACKEND_URL=http://127.0.0.1:5000/analyse_email

USER user
WORKDIR $HOME/app

COPY --chown=user requirements-space.txt ./
RUN pip install --upgrade pip && pip install -r requirements-space.txt

COPY --chown=user . .
RUN chmod +x start.sh

EXPOSE 7860

CMD ["./start.sh"]
