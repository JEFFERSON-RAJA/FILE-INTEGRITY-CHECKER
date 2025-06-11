# FILE-INTEGRITY-CHECKER

COMPANY : JEFFERSON RAJA A 

INTERN ID : CT04DN1133

DOMAIN : Cyber Security & Ethical Hacking 

DURATION : 4 WEEKS

MENTOR : NEELA SANTHOSH

DESCRIPTION

File Integrity Checker
This Python script provides a comprehensive file integrity checking solution by monitoring file changes through cryptographic hashing and metadata comparison.

Core Functionality

Hashing Algorithms
1.Supports multiple hash algorithms (SHA-256 by default)
2.efficient hash calculation with progress reporting
3.Parallel processing for improved performance

Baseline Management
1.Creates compressed snapshots of file states
2.Stores file hashes with metadata (size, timestamps, permissions)
3.Version-controlled baseline format
4.Atomic write operations for data safety

Integrity Verification
1.Compares current file states against baseline
2.Detects:
 1.Content changes (via hash comparison)
 2.Metadata modifications (size, timestamps)
 3.Permission changes
 4.New/deleted files
