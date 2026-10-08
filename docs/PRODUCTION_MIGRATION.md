# PRAMAAN - Production Migration Guide

**Version:** 1.0

Covers technical migration for five subsystems: Docker, AWS RDS (PostgreSQL), Neo4j AuraDB, Celery + SQS, AWS Secrets Manager. Companion to DEPLOYMENT_PLAN.md.

## 1. Containerization - Docker

Current state: docker-compose.yml provisions Neo4j only. No Dockerfile.

Target services: pramaan-app (8501, 8000), pramaan-worker, pramaan-redis.

Example Dockerfile:

    FROM python:3.13-slim
    ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
    WORKDIR /app
    RUN apt-get update && apt-get install -y --no-install-recommends build-essential curl
    COPY requirements.txt .
    RUN pip install --no-cache-dir -r requirements.txt
    COPY . .
    EXPOSE 8501 8000
    CMD [streamlit, run, app.py, --server.address=0.0.0.0, --server.port=8501]

Example docker-compose.prod.yml:

    version: 3.9
    services:
      app:
        build: .
        ports: [8501:8501, 8000:8000]
        environment: [PRAMAAN_ENV=production]
      worker:
        build: .
        command: celery -A backend.queue.celery_app worker --loglevel=info
      redis:
        image: redis:7-alpine

## 2. Database - SQLite to AWS RDS PostgreSQL

Current state: SQLite on zkvf_ledger.db (zkfv.py 3 sites, api.py:322).

Target: PostgreSQL 16 on RDS, Multi-AZ, KMS encryption, TLS enforced.

Migration: add backend/db/connection.py reading PRAMAAN_DB_URL; refactor zkvf.py and api.py; one-off migrate_sqlite_to_pg.py script.

RDS settings: db.t4g.medium, 100 GB gp3, Multi-AZ yes, backup 14 days, KMS encryption, no public access.

## 3. Graph - Local Neo4j to AuraDB

Current state: neo4j_engine.py connects to bolt://localhost:7687 with NetworkX fallback.

Target: AuraDB Professional, region ap-south-1, 2 GB RAM.

Migration: update neo4j_engine.py to read credentials from Secrets Manager; keep NetworkX fallback; export local via neo4j-admin dump.

## 4. Async - Celery plus AWS SQS

Current state: no background task queue.

Target: Celery workers consuming from SQS. Add backend/queue/celery_app.py and backend/queue/tasks.py.

Example celery_app.py:

    import os
    from celery import Celery
    celery_app = Celery(
        pramaan,
        broker=os.getenv(CELERY_BROKER_URL, sqs://),
        backend=os.getenv(CELERY_RESULT_BACKEND, redis://redis:6379/0),
    )
    celery_app.conf.update(task_serializer=json, timezone=UTC, enable_utc=True)

SQS settings: queue pramaan-tasks, Standard type, visibility timeout 3600 s, DLQ after 3 failures, SSE-SQS encryption.

## 5. Secrets - Env vars to AWS Secrets Manager

Current state: env vars only. blockchain/anchor.py reads SEPOLIA_RPC_URL and ANALYST_PRIVATE_KEY.

Target secrets: pramaan/db, pramaan/neo4j, pramaan/blockchain, pramaan/intel.

Example backend/secrets/aws.py:

    import json, os
    from functools import lru_cache
    import boto3

    @lru_cache(maxsize=32)
    def get_secret(name):
        if os.getenv(PRAMAAN_USE_AWS_SECRETS, false).lower() != true:
            return {}
        client = boto3.client(secretsmanager, region_name=os.getenv(AWS_REGION, ap-south-1))
        return json.loads(client.get_secret_value(SecretId=name)[SecretString])

Migration: create backend/secrets/, refactor anchor.py and neo4j_engine.py and zkvf.py to use get_secret; add boto3 to requirements.txt.

## 6. Migration order

1. Docker (containerize)
2. AWS Secrets Manager (unblocks rest)
3. Neo4j to AuraDB (low risk)
4. SQLite to RDS (data migration)
5. Celery + SQS (new code)

Each step is a separate PR.

## 7. Testing strategy

Local fallbacks for all subsystems. Staging tests use real AWS / AuraDB instances.

## 8. Rollback plan

Every subsystem has an env-var fallback:
- Docker: old process launch
- RDS: SQLite if PRAMAAN_DB_URL unset
- AuraDB: NetworkX fallback
- Celery: synchronous if CELERY_BROKER_URL unset
- Secrets: env vars if PRAMAAN_USE_AWS_SECRETS != true

No migration is a hard cutover.

## 9. Open questions

- Multi-tenant isolation: RDS schemas vs separate databases?
- HSM for signer keys: YubiHSM vs AWS KMS?
- Keep Sepolia as public anchor alongside permissioned chain?
- DPDP Act 2023 retention window for evidence?
