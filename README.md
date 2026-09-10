# SCV 4.5.3 — Wordpress Backdoor Analysis & Decoder Tools

SCV 4.5.3 is an active WordPress backdoor family using Ethereum blockchain dead-drop resolvers ("EtherHiding") for C2. Malware disguised as fake plugins, self-healing (tug-of-war persistence), credential harvesting via service worker, admin session theft.

## IOCs

### Ethereum Contracts (C2 resolver — eth_call selector 0x3bc5de30)
- `0x9A4752cAA1C15868487A0ACb691F81bfA901E063`
- `0x839d1cE5c3F259e8d3D17114d7186EDabdbeA94b`
- `0x6d2c5435EF70196740a48904B69377935D50abBB`

### On-chain update function
- `setData(bytes)` = selector `0xab62f0e1`
- Guard: `require(msg.sender == manager)` — only manager wallet can update C2 list

### Wallets (single operator)
- **Manager** (updates C2 via setData): `0x25118258e13c810794343cfc858454674803fdf5`
- **Deployer** (create contracts, setManager): `0xa9a95a9e8e85e97b52b72d8dd6a106973314b9c4`

[BlockScout: manager](https://eth.blockscout.com/address/0x25118258e13c810794343cfc858454674803fdf5) | [deployer](https://eth.blockscout.com/address/0xa9a95a9e8e85e97b52b72d8dd6a106973314b9c4)

### Encryption Key
`33236f30a93bf4da9a985a080f1e93b9` (16 bytes, shared across all contracts)

### Sample Hashes
| Sample | SHA256 |
|--------|--------|
| c4f9daf9.zip (ZIP) | `245b03debfe364092f6e32fc1213cf1d285f2faecaade1ef2fc33ddd114e600b` |
| bold-booster-lab.php (malware inside ZIP) | `53371084bb1f341b38bf20dca934710d9ab642890a50f599564096008cea8bf7` |
| castle variant (live C2 pull) | `d6eff32d0b0917148341224ae351a72d15a20810fa38304dd6cf995a045be23b` |
| pyramid variant (live C2 pull) | `3af0b1610abccb7fde672e6dbf7942304769d923673bfa59cef3b10b510d50e5` |

### C2 Domains (rotation history)
> All currently dead/suspended. See [`evidence/`](evidence/) for full rotation CSV.

Batch 1 (registered May-Jun 2026):
`carpet-sail.com seat-aviation.com fashion-chicken.com`

Batch 2 (Jul-Aug):
`siege-close.com root-cherry.com forecast-chaos.com sound-obstacle.com basic-junior.com railroad-boot.com great-basic.com`

Batch 3 (08-Sep-2026):
`castle-lid.com highlight-pyramid.com`

Batch 4 (09-Sep-2026, post-report):
`notion-brown.com gear-carriage.com tape-exposure.com`

### Service Worker (browser persistence)
- `blob1101.bin` — SHA256 available on request
- Intercepts wp-login.php POST → steals credentials
- Injects code into wp-admin/* pages
- Background Sync beacon (`sc-sync`)
- Sample provided in [`evidence/`](evidence/)

## Markers on Server
- Files: `wp-content/mu-plugins/*.php` containing `/* SCV:4.5.3 */`
- Guard files: `.g_`, `.gl_`, `.sd_`, `.bt_`, `.swm_`, `.q_`, `.rd_`, `.mu_st_`, `.mu_lk_` in wp-content
- DB options (autoload=no): `sc_*`, `bu`, `bp`, `ic`, `ck_pend`, `ck_commit`, `adminsCookies`
- Hidden admin users: `admin_*`, `adm_*`, `administrator_*`, `backup_*` + 6-10 hex suffix

## Scanner rules (Sigma/YARA)
Coming soon. For now use grep:
```
grep -r 'SCV:4.5.3' wp-content/
grep -r 'sc_payload_persistent' wp-content/
php -r 'foreach(get_option("bu",[]) as $u) echo "Hidden admin: $u\n";'
```

## Decoder Tools
Python 3 scripts in [`decoders/`](decoders/):

| Script | Purpose |
|--------|---------|
| `decode_scv.py` | Static decode SCV string table (no execution) |
| `decode_ddr.py` | Decode EtherHiding dead-drop from eth_call output |
| `probe_c2.py` | Read-only C2 beacon probe (canary creds, no live payload) |

## References
- Monarx: "The WordPress infection that rebuilds itself faster than you can delete it" (Aug 2026)
- CVE-2026-32475: Elementor Pro <=4.2.1 unauth file upload RCE (observed entry vector)
- mdpabel.com SC 4.0.3 analysis (Aug 2026)

## License
Public — share freely. Attribution appreciated but not required.

## Contact
- Open an issue or PR
- Report new variant IOCs via GitHub issues