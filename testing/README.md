# Fenceline Testing Simulations

Safe, localhost-only simulations of real supply chain attack patterns. These tests help validate that detection tools can identify malicious behavior without using real malware or connecting to external servers.

## Safety Guarantees

- **All simulations use localhost only** — no connections leave your machine
- **No real malware** — each test simulates the network pattern of a known attack, not the payload
- **Safe to run on any development machine** — nothing is installed, modified, or persisted
- **Idempotent** — each test cleans up after itself

## What's Tested

Each simulation recreates the network behavior of a documented supply chain attack:

| Test | Attack Pattern | Real-World Example |
|------|---------------|-------------------|
| `test-outbound-exfil.sh` | Data exfiltration via outbound HTTP | event-stream, Codecov, Axios |
| `test-postinstall.sh` | Malicious postinstall script spawning processes | ua-parser-js, Nx |
| `test-mining-pool.sh` | Cryptocurrency mining pool connection | Ultralytics |
| `test-dns-exfil.sh` | DNS-based data exfiltration | Various |
| `test-child-process.sh` | Child process spawning outbound connections | Nx (node -> curl -> C2) |

## Running Tests

Run individual tests:

```bash
cd testing/simulations
./test-outbound-exfil.sh
```

Run all tests with the harness:

```bash
./harness.sh
```

The harness generates a summary report in `reports/`.

## How to Read Results

Each test prints three sections:

1. **SETUP** — What the test is configuring (localhost servers, mock processes)
2. **SIMULATION** — The actual attack pattern being executed
3. **DETECTION POINTS** — What a detector should have caught, with specific indicators

A detection tool should flag every item listed in DETECTION POINTS. If it misses any, that's a gap.

## Writing New Simulations

Follow the existing pattern:

1. Name the file `test-<pattern>.sh`
2. Document which real attack it simulates in the header comment
3. Use only localhost (127.0.0.1) for all network activity
4. Clean up all spawned processes in a trap handler
5. Print clear DETECTION POINTS at the end

## License

Apache 2.0 — see [LICENSE](../LICENSE) in the project root.
