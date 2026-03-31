# Fenceline Detection Report

- **Date:** YYYY-MM-DDTHH:MM:SSZ
- **Detector:** (name and version of the detection tool being tested)
- **Tests run:** N
- **Detected:** N
- **Missed:** N

## Summary

Brief description of what was tested and the overall results.

## Results

| Test | Attack Pattern | Detected | Detection Method | Notes |
|------|---------------|----------|-----------------|-------|
| test-outbound-exfil | HTTP exfiltration | YES/NO | (how it was detected) | |
| test-postinstall | Malicious postinstall | YES/NO | (how it was detected) | |
| test-mining-pool | Mining pool connection | YES/NO | (how it was detected) | |
| test-dns-exfil | DNS exfiltration | YES/NO | (how it was detected) | |
| test-child-process | Child process C2 | YES/NO | (how it was detected) | |

## Detection Details

### test-outbound-exfil

- **Expected indicators:**
  - Outbound HTTP to non-registry IP
  - Sensitive data in request body/URL
  - Non-standard port (not 443)
- **Detected indicators:** (list what the detector caught)
- **Missed indicators:** (list what the detector missed)
- **Time to detect:** (how quickly after the connection was made)

### test-postinstall

- **Expected indicators:**
  - Child process spawned from install hook
  - Network connection from child process
  - Sensitive file access
- **Detected indicators:** (list what the detector caught)
- **Missed indicators:** (list what the detector missed)
- **Time to detect:** (how quickly)

### test-mining-pool

- **Expected indicators:**
  - Connection to non-standard port (3333, 4444, etc.)
  - Stratum protocol pattern
  - Destination not in known CDN ranges
- **Detected indicators:** (list what the detector caught)
- **Missed indicators:** (list what the detector missed)
- **Time to detect:** (how quickly)

### test-dns-exfil

- **Expected indicators:**
  - Unusually long subdomain labels
  - Hex/base64 encoded subdomains
  - Queries to unknown domains
- **Detected indicators:** (list what the detector caught)
- **Missed indicators:** (list what the detector missed)
- **Time to detect:** (how quickly)

### test-child-process

- **Expected indicators:**
  - Suspicious process tree (node -> sh -> curl)
  - Indirect network access from child
  - Delayed/background execution
- **Detected indicators:** (list what the detector caught)
- **Missed indicators:** (list what the detector missed)
- **Time to detect:** (how quickly)

## Gaps

List any attack patterns that the detector consistently missed or was slow to detect.

## Recommendations

Suggestions for improving detection based on the test results.

## Environment

- **OS:** (operating system and version)
- **Arch:** (CPU architecture)
- **Shell:** (shell used)
- **Node version:** (if applicable)
- **Python version:** (if applicable)
