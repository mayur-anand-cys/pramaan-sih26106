"""Neo4j connection manager for PRAMAAN."""
import os
from typing import Optional
from contextlib import contextmanager
from neo4j import GraphDatabase, Driver


class Neo4jClient:
    _instance: Optional["Neo4jClient"] = None
    _driver: Optional[Driver] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def connect(self) -> Driver:
        if self._driver is None:
            uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
            user = os.getenv("NEO4J_USER", "neo4j")
            password = os.getenv("NEO4J_PASSWORD", "pramaan_dev")
            self._driver = GraphDatabase.driver(uri, auth=(user, password))
        return self._driver

    def close(self):
        if self._driver:
            self._driver.close()
            self._driver = None

    @contextmanager
    def session(self):
        driver = self.connect()
        session = driver.session()
        try:
            yield session
        finally:
            session.close()

    def verify_connection(self) -> bool:
        try:
            with self.session() as s:
                s.run("RETURN 1")
            return True
        except Exception:
            return False


def init_schema():
    with Neo4jClient().session() as session:
        constraints = [
            "CREATE CONSTRAINT email_id IF NOT EXISTS FOR (e:Email) REQUIRE e.id IS UNIQUE",
            "CREATE CONSTRAINT ip_addr IF NOT EXISTS FOR (i:IPAddress) REQUIRE i.address IS UNIQUE",
            "CREATE CONSTRAINT asn_num IF NOT EXISTS FOR (a:ASN) REQUIRE a.number IS UNIQUE",
            "CREATE CONSTRAINT domain_name IF NOT EXISTS FOR (d:Domain) REQUIRE d.name IS UNIQUE",
            "CREATE CONSTRAINT hash_val IF NOT EXISTS FOR (h:FileHash) REQUIRE h.value IS UNIQUE",
            "CREATE CONSTRAINT campaign_id IF NOT EXISTS FOR (c:Campaign) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT user_email IF NOT EXISTS FOR (u:TargetedUser) REQUIRE u.email IS UNIQUE",
        ]
        for c in constraints:
            session.run(c)

        indexes = [
            "CREATE INDEX email_received IF NOT EXISTS FOR (e:Email) ON (e.received_at)",
            "CREATE INDEX email_score IF NOT EXISTS FOR (e:Email) ON (e.threat_score)",
            "CREATE INDEX campaign_score IF NOT EXISTS FOR (c:Campaign) ON (c.confidence)",
        ]
        for i in indexes:
            session.run(i)
