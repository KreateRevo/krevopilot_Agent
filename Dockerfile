FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /agent

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent.py collector.py privacy.py test_agent.py VERSION ./
COPY scripts/verify_release.py ./scripts/verify_release.py

RUN python scripts/verify_release.py --chart-dir charts/krevopilot-agent --agent-only && \
    python -m unittest -v test_agent.py

RUN useradd --system --uid 10001 --no-create-home agent
USER 10001:10001

CMD ["python", "agent.py"]
