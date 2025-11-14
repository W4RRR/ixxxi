# ixxxi
`ixxi.sh` is an orchestration script that first runs Hadixxity to build a high-level attack surface map for a target domain, then feeds its discovered apex domains and subdomains into SUPERECON to perform deep web reconnaissance. All results are stored in a single `recon-&lt;domain>` directory for a unified, organized view of the target.
