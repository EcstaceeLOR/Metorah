"""Transactional SQLite cursor and canonical-event persistence for destination indexers.

SQLite is appropriate for a single-worker deployment. Use one database per destination
chain and migration; do not share one writer across distributed workers.
"""
import sqlite3
from tools.destination.indexer import DestinationProjection, IndexedEvent, DestinationError


class SQLiteProjectionStore:
    def __init__(self, path: str, chain_id: int):
        if chain_id <= 0:
            raise DestinationError("invalid_chain_id")
        self.path, self.chain_id = path, chain_id
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS destination_blocks (
                    chain_id INTEGER NOT NULL, height INTEGER NOT NULL, block_hash TEXT NOT NULL,
                    PRIMARY KEY (chain_id, height)
                );
                CREATE TABLE IF NOT EXISTS destination_events (
                    chain_id INTEGER NOT NULL, tx_hash TEXT NOT NULL, log_index INTEGER NOT NULL,
                    height INTEGER NOT NULL, block_hash TEXT NOT NULL, contract TEXT NOT NULL,
                    topic0 TEXT NOT NULL, topics TEXT NOT NULL, data TEXT NOT NULL,
                    PRIMARY KEY (chain_id, tx_hash, log_index)
                );
                CREATE INDEX IF NOT EXISTS destination_events_height
                    ON destination_events (chain_id, height);
            """)

    def _connect(self):
        return sqlite3.connect(self.path, timeout=30)

    def load(self) -> DestinationProjection:
        import json
        with self._connect() as db:
            blocks = {int(n): h for n, h in db.execute(
                "SELECT height,block_hash FROM destination_blocks WHERE chain_id=? ORDER BY height",
                (self.chain_id,),
            )}
            events = {}
            for tx, idx, height, block_hash, contract, topic0, topics, data in db.execute(
                "SELECT tx_hash,log_index,height,block_hash,contract,topic0,topics,data "
                "FROM destination_events WHERE chain_id=?", (self.chain_id,),
            ):
                event = IndexedEvent(self.chain_id, height, block_hash, tx, idx,
                                     contract, topic0, tuple(json.loads(topics)), data)
                if blocks.get(height) != block_hash:
                    raise DestinationError("persisted_event_not_canonical")
                events[(tx, idx)] = event
        return DestinationProjection(blocks, events, max(blocks, default=-1))

    def replace_from(self, from_block: int, blocks: list[tuple[int, str]],
                     events: list[IndexedEvent]) -> DestinationProjection:
        import json
        # Validate a complete new projection before mutating the database.
        candidate = self.load()
        candidate.replace_from(from_block, blocks, events)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM destination_events WHERE chain_id=? AND height>=?",
                       (self.chain_id, from_block))
            db.execute("DELETE FROM destination_blocks WHERE chain_id=? AND height>=?",
                       (self.chain_id, from_block))
            db.executemany(
                "INSERT INTO destination_blocks (chain_id,height,block_hash) VALUES (?,?,?)",
                [(self.chain_id, n, h) for n, h in blocks],
            )
            db.executemany(
                "INSERT INTO destination_events "
                "(chain_id,tx_hash,log_index,height,block_hash,contract,topic0,topics,data) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                [(self.chain_id, e.tx_hash, e.log_index, e.block_number, e.block_hash,
                  e.contract, e.topic0, json.dumps(e.topics), e.data) for e in events],
            )
        return candidate
