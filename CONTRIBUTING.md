# Contributing to Fenceline

Thank you for your interest in contributing. Every contribution helps make the software supply chain safer for everyone.

## Ways to Contribute

### Documentation (Highest Impact)

The documentation IS the product. Improvements here help the most people:

- **Fix errors** — typos, outdated information, broken links
- **Improve clarity** — if something is confusing, make it clearer
- **Add context** — additional details, alternative perspectives, better examples
- **Translate** — make content accessible in more languages

### Exploit Case Studies

- **Add new incidents** — use `exploits/template.md` as your starting point
- **Update existing cases** — add new information as it becomes available
- **Add references** — link to new reports, blog posts, or analyses
- **Verify IOCs** — confirm or correct network indicators of compromise

### The Deep Map

- **Add new tools** — document expected network behavior for tools we haven't covered
- **Update data** — IPs rotate, certificates renew, CDNs change
- **Verify entries** — run the tool and confirm our map matches reality
- **Add depth** — TLS fingerprints, HTTP methods, expected payload sizes

### Detection Tools

- **Build new plugins** — detection signals we haven't implemented
- **Improve existing tools** — better accuracy, fewer false positives
- **Port to new platforms** — Linux, Windows support
- **Add tests** — new attack pattern simulations

## How to Submit

1. Fork the repository
2. Create a branch (`git checkout -b add-new-exploit-case`)
3. Make your changes
4. Test locally if applicable
5. Submit a pull request with a clear description

## Guidelines

### For Documentation

- Write for developers who are NOT security experts
- Use plain language — avoid jargon where possible
- Include sources and references for claims
- Date your contributions — security information ages fast

### For Exploit Case Studies

- Follow the template in `exploits/template.md`
- Include primary source links (original reports, CVEs, advisories)
- Be precise about network IOCs (domains, IPs, ports)
- Include the "Could Fenceline Catch This?" section
- Mark any unverified information as such

### For Map Data

- Include your data source (DNS lookup, official docs, source code, etc.)
- Note the date of your observation — IPs and certs change
- Follow the schema in `map/schema.yaml`
- Don't remove existing data without explanation

### For Code

- Keep it simple — readable code over clever code
- No unnecessary dependencies
- Test against the attack simulations in `testing/`
- Document what it does and what it catches

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). We are committed to a welcoming, respectful community.

## Questions?

Open a GitHub Issue. There are no stupid questions — if you're confused, others probably are too, and your question might improve the documentation.
