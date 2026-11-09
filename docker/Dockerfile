FROM python:3.13-slim-bookworm
RUN groupadd --gid 10001 dlp && useradd --uid 10001 --gid dlp --no-create-home dlp \
    && mkdir -p /var/lib/dlp-central /app/dlp \
    && chown dlp:dlp /var/lib/dlp-central && chmod 0700 /var/lib/dlp-central
WORKDIR /app
# Policy validation on upload needs the same schema code and PyYAML pin as the agents.
RUN pip install --no-cache-dir PyYAML==6.0.3
COPY src/dlp/__init__.py src/dlp/central.py src/dlp/remote_control.py src/dlp/policy_channel.py src/dlp/policy.py src/dlp/models.py src/dlp/file_types.py src/dlp/central_page.html src/dlp/central_ui.js /app/dlp/
COPY docker/entrypoint.py /app/entrypoint.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8766
ENTRYPOINT ["python3", "/app/entrypoint.py"]
CMD ["serve"]
