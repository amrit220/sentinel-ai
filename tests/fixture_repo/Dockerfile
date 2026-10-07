FROM python:3.11-slim
# INTENTIONAL flaws: runs as root, pipes downloads into shell, baked-in secret
ENV ADMIN_TOKEN=fxt_docker_admin_token_555
RUN curl -sSL https://example.com/install.sh | bash
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "app.py"]
