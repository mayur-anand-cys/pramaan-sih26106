// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PramaanEvidence {

    struct Evidence {
        string  caseId;
        string  merkleRoot;
        string  fileSha256;
        uint256 timestamp;
        address analyst;
        string  classification;
    }

    mapping(string => Evidence) private records;
    mapping(string => bool) private exists;
    uint256 public totalAnchored;

    event EvidenceAnchored(
        string indexed caseId,
        string fileSha256,
        string merkleRoot,
        uint256 timestamp,
        address indexed analyst,
        string classification
    );

    event VerificationResult(
        string indexed caseId,
        bool verified,
        uint256 timestamp
    );

    function anchorEvidence(
        string memory _caseId,
        string memory _merkleRoot,
        string memory _fileSha256,
        string memory _classification
    ) public {
        require(!exists[_caseId], "PRAMAAN: Case already anchored");
        require(bytes(_caseId).length > 0, "PRAMAAN: Empty caseId");
        require(bytes(_merkleRoot).length > 0, "PRAMAAN: Empty merkleRoot");
        require(bytes(_fileSha256).length == 64, "PRAMAAN: SHA-256 must be 64 chars");

        records[_caseId] = Evidence({
            caseId: _caseId,
            merkleRoot: _merkleRoot,
            fileSha256: _fileSha256,
            timestamp: block.timestamp,
            analyst: msg.sender,
            classification: _classification
        });

        exists[_caseId] = true;
        totalAnchored += 1;

        emit EvidenceAnchored(
            _caseId,
            _fileSha256,
            _merkleRoot,
            block.timestamp,
            msg.sender,
            _classification
        );
    }

    function verifyEvidence(
        string memory _caseId,
        string memory _merkleRoot
    ) public returns (bool) {
        require(exists[_caseId], "PRAMAAN: Case not found");
        Evidence memory e = records[_caseId];
        bool ok = keccak256(bytes(e.merkleRoot)) == keccak256(bytes(_merkleRoot));
        emit VerificationResult(_caseId, ok, block.timestamp);
        return ok;
    }

    function getEvidence(string memory _caseId)
        public
        view
        returns (Evidence memory)
    {
        require(exists[_caseId], "PRAMAAN: Case not found");
        return records[_caseId];
    }

    function isAnchored(string memory _caseId) public view returns (bool) {
        return exists[_caseId];
    }
}