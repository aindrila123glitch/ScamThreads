// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

contract Registry {
    enum Status { Submitted, Validated, Disputed, Superseded }

    struct Report {
        address reporter;
        uint64 timestamp;
        bytes32 evidenceRoot;
        uint8 category; // 0: URL/Web, 1: Message/Phish, 2: Payload/File, 3: Cert/Infrastructure
        uint8 status;   // 0: Submitted, 1: Validated, 2: Disputed, 3: Superseded
        bytes32 supersededBy;
        uint32 validations;
        uint32 disputes;
    }

    mapping(bytes32 => uint256) public recordedAt;
    mapping(bytes32 => Report) public reports;
    mapping(bytes32 => mapping(address => bool)) public hasActed;
    mapping(address => bytes32[]) private reporterHistory;

    event Registered(bytes32 indexed commitment, address indexed reporter, bytes32 evidenceRoot, uint8 category);
    event Revised(bytes32 indexed oldCommitment, bytes32 indexed newCommitment, address indexed reporter);
    event Validated(bytes32 indexed commitment, address indexed validator, uint32 count);
    event Disputed(bytes32 indexed commitment, address indexed disputer, bytes32 reasonHash, uint32 count);

    // Backwards compatible v1 register
    function register(bytes32 commitment) external {
        _register(commitment, bytes32(0), 0);
    }

    function register(bytes32 commitment, bytes32 evidenceRoot, uint8 category) external {
        _register(commitment, evidenceRoot, category);
    }

    function _register(bytes32 commitment, bytes32 evidenceRoot, uint8 category) internal {
        require(commitment != bytes32(0) && recordedAt[commitment] == 0, "Invalid or duplicate");
        recordedAt[commitment] = block.timestamp;

        Report storage rep = reports[commitment];
        rep.reporter = msg.sender;
        rep.timestamp = uint64(block.timestamp);
        rep.evidenceRoot = evidenceRoot;
        rep.category = category;
        rep.status = uint8(Status.Submitted);

        hasActed[commitment][msg.sender] = true;
        reporterHistory[msg.sender].push(commitment);

        emit Registered(commitment, msg.sender, evidenceRoot, category);
    }

    function revise(bytes32 oldCommitment, bytes32 newCommitment, bytes32 newRoot) external {
        Report storage oldRep = reports[oldCommitment];
        require(oldRep.reporter == msg.sender, "Only original reporter can revise");
        require(oldRep.status != uint8(Status.Superseded), "Already superseded");
        require(newCommitment != bytes32(0) && recordedAt[newCommitment] == 0, "Invalid new commitment");

        oldRep.status = uint8(Status.Superseded);
        oldRep.supersededBy = newCommitment;

        _register(newCommitment, newRoot, oldRep.category);
        emit Revised(oldCommitment, newCommitment, msg.sender);
    }

    function validate(bytes32 commitment) external {
        require(recordedAt[commitment] != 0, "Report not found");
        require(!hasActed[commitment][msg.sender], "Already acted or reporter");
        Report storage rep = reports[commitment];
        require(rep.status != uint8(Status.Superseded), "Report is superseded");

        hasActed[commitment][msg.sender] = true;
        rep.validations += 1;

        if (rep.validations >= 2 && rep.validations > rep.disputes) {
            rep.status = uint8(Status.Validated);
        }

        emit Validated(commitment, msg.sender, rep.validations);
    }

    function dispute(bytes32 commitment, bytes32 reasonHash) external {
        require(recordedAt[commitment] != 0, "Report not found");
        require(!hasActed[commitment][msg.sender], "Already acted or reporter");
        Report storage rep = reports[commitment];
        require(rep.status != uint8(Status.Superseded), "Report is superseded");

        hasActed[commitment][msg.sender] = true;
        rep.disputes += 1;

        if (rep.disputes >= 2 && rep.disputes >= rep.validations) {
            rep.status = uint8(Status.Disputed);
        }

        emit Disputed(commitment, msg.sender, reasonHash, rep.disputes);
    }

    function getReport(bytes32 commitment) external view returns (Report memory) {
        require(recordedAt[commitment] != 0, "Report not found");
        return reports[commitment];
    }

    function historyOf(address reporter) external view returns (bytes32[] memory) {
        return reporterHistory[reporter];
    }
}
