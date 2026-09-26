"""PRAMAAN blockchain anchor — Web3.py + Sepolia."""
import os
import json
import logging
from typing import Dict, Any, Optional

try:
    from web3 import Web3
    from eth_account import Account
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False

logger = logging.getLogger("pramaan.blockchain")

SEPOLIA_RPC_URL = os.getenv(
    "SEPOLIA_RPC_URL",
    "https://ethereum-sepolia-rpc.publicnode.com"
)
ANALYST_PRIVATE_KEY = os.getenv("ANALYST_PRIVATE_KEY", "")
CONTRACT_ADDRESS = os.getenv("PRAMAAN_CONTRACT_ADDRESS", "")
CONTRACT_ABI_JSON = os.getenv("PRAMAAN_CONTRACT_ABI", "")


def _load_abi() -> list:
    if CONTRACT_ABI_JSON:
        try:
            return json.loads(CONTRACT_ABI_JSON)
        except Exception:
            pass
    return [
        {
            "inputs": [
                {"name": "_caseId", "type": "string"},
                {"name": "_merkleRoot", "type": "string"},
                {"name": "_fileSha256", "type": "string"},
                {"name": "_classification", "type": "string"},
            ],
            "name": "anchorEvidence",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [
                {"name": "_caseId", "type": "string"},
                {"name": "_merkleRoot", "type": "string"},
            ],
            "name": "verifyEvidence",
            "outputs": [{"name": "", "type": "bool"}],
            "stateMutability": "nonpayable",
            "type": "function",
        },
        {
            "inputs": [{"name": "_caseId", "type": "string"}],
            "name": "getEvidence",
            "outputs": [
                {
                    "components": [
                        {"name": "caseId", "type": "string"},
                        {"name": "merkleRoot", "type": "string"},
                        {"name": "fileSha256", "type": "string"},
                        {"name": "timestamp", "type": "uint256"},
                        {"name": "analyst", "type": "address"},
                        {"name": "classification", "type": "string"},
                    ],
                    "name": "",
                    "type": "tuple",
                }
            ],
            "stateMutability": "view",
            "type": "function",
        },
    ]


def _get_web3() -> Optional[Any]:
    if not WEB3_AVAILABLE:
        return None
    try:
        w3 = Web3(Web3.HTTPProvider(SEPOLIA_RPC_URL, request_kwargs={"timeout": 10}))
        if not w3.is_connected():
            return None
        return w3
    except Exception as e:
        logger.warning(f"Web3 connection failed: {e}")
        return None


def anchor_evidence(
    case_id: str,
    merkle_root: str,
    file_sha256: str,
    classification: str = "UNKNOWN",
) -> Dict[str, Any]:
    """Anchor an evidence package to Sepolia."""
    if not case_id or not merkle_root or not file_sha256:
        return {
            "success": False,
            "storage": "ERROR",
            "error": "Missing required parameters",
        }

    if len(file_sha256) != 64:
        return {
            "success": False,
            "storage": "ERROR",
            "error": "file_sha256 must be 64 hex chars",
        }

    w3 = _get_web3()

    if w3 is None or not ANALYST_PRIVATE_KEY or not CONTRACT_ADDRESS:
        return {
            "success": True,
            "storage": "SIMULATED",
            "tx_hash": f"0x_simulated_{case_id[:8]}_{merkle_root[:8]}",
            "block_number": None,
            "explorer_url": None,
            "note": "Blockchain not configured. Set SEPOLIA_RPC_URL, ANALYST_PRIVATE_KEY, PRAMAAN_CONTRACT_ADDRESS for real anchor.",
        }

    try:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=_load_abi(),
        )

        account = Account.from_key(ANALYST_PRIVATE_KEY)
        nonce = w3.eth.get_transaction_count(account.address)

        txn = contract.functions.anchorEvidence(
            case_id,
            merkle_root,
            file_sha256,
            classification,
        ).build_transaction({
            "chainId": 11155111,
            "gas": 300000,
            "maxFeePerGas": w3.to_wei("30", "gwei"),
            "maxPriorityFeePerGas": w3.to_wei("2", "gwei"),
            "nonce": nonce,
            "from": account.address,
        })

        signed = account.sign_transaction(txn)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_hash_hex = w3.to_hex(tx_hash)

        try:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
            block_number = receipt.blockNumber
        except Exception:
            block_number = None

        return {
            "success": True,
            "storage": "SEPOLIA",
            "tx_hash": tx_hash_hex,
            "block_number": block_number,
            "explorer_url": f"https://sepolia.etherscan.io/tx/{tx_hash_hex}",
            "case_id": case_id,
            "merkle_root": merkle_root,
        }

    except Exception as e:
        logger.error(f"Blockchain anchor failed: {e}")
        return {
            "success": False,
            "storage": "ERROR",
            "error": str(e)[:200],
        }


def verify_evidence(case_id: str, merkle_root: str) -> Dict[str, Any]:
    """Verify a case's anchored Merkle root."""
    w3 = _get_web3()

    if w3 is None or not CONTRACT_ADDRESS:
        return {
            "verified": None,
            "storage": "SIMULATED",
            "note": "Blockchain not configured",
        }

    try:
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(CONTRACT_ADDRESS),
            abi=_load_abi(),
        )
        record = contract.functions.getEvidence(case_id).call()
        anchored_root = record[1]
        matches = anchored_root.lower() == merkle_root.lower()

        return {
            "verified": matches,
            "storage": "SEPOLIA",
            "case_id": case_id,
            "anchored_root": anchored_root,
            "provided_root": merkle_root,
            "timestamp": record[3],
            "analyst": record[4],
            "classification": record[5],
        }
    except Exception as e:
        return {
            "verified": None,
            "storage": "ERROR",
            "error": str(e)[:200],
        }


def blockchain_status() -> Dict[str, Any]:
    """Health check for blockchain config."""
    w3 = _get_web3()
    return {
        "web3_available": WEB3_AVAILABLE,
        "connected": w3 is not None,
        "rpc_url": SEPOLIA_RPC_URL if w3 else None,
        "contract_configured": bool(CONTRACT_ADDRESS),
        "signer_configured": bool(ANALYST_PRIVATE_KEY),
        "mode": "LIVE" if (w3 and CONTRACT_ADDRESS and ANALYST_PRIVATE_KEY) else "SIMULATED",
    }