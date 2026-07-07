# The Yard Browser — Development Status
### Last updated: July 2026

---

## Build Environment

- **Base**: LibreWolf 152.0.2 (Firefox 152.0.2 fork)
- **Build machine**: Hetzner Cloud VPS (x86_64 Ubuntu 24.04, CX52 — 8 vCPU / 16GB RAM)
- **Why Hetzner**: M1 Mac cannot cross-compile x86_64 Linux binaries. ARM64 LTO link step is reliably OOM-killed regardless of RAM.
- **Snapshot workflow**: Build on Hetzner → snapshot → destroy server → restore for next session. Costs ~€1–4/month.
- **Current snapshot name**: `yard-build-152-csm-whitelist`
- **Dev machine**: M1 Mac (username `theswintfamily`)
- **Test machine**: Linux VM via UTM at `192.168.64.6` (username `yard`)
- **Source repo**: Codeberg (primary) + GitHub mirror at `Rock-Gungadee/theyard-browser`
- **Build command**: `make build` from `~/theyard-browser/` on Hetzner
- **Incremental build time**: ~20–30 seconds for single-file changes; full build ~2–3 hours

### Build flags (in mozconfig)
```
mk_add_options MOZ_MAKE_FLAGS="-j4"
ac_add_options --disable-debug
ac_add_options --enable-linker=lld
```

### Swap required
The LTO link step spikes memory. Always ensure `/swapfile` (16GB) is active before building:
```bash
swapon /swapfile
```

---

## Completed Milestones

### ✅ Milestone 1 — Base binary compiles
LibreWolf 152.0.2 builds successfully on Hetzner x86_64. Binary runs on Ubuntu 24.04 VM.

### ✅ Milestone 2 — `yard://` protocol handler
The `yard://` scheme is registered in Gecko and renders content in the browser.

**Files added:**
- `netwerk/protocol/yard/nsYardProtocolHandler.h`
- `netwerk/protocol/yard/nsYardProtocolHandler.cpp`
- `netwerk/protocol/yard/moz.build`

**Files modified:**
- `netwerk/protocol/moz.build` — added `"yard"` to `DIRS`
- `netwerk/build/components.conf` — registered handler via `Classes +=` block
- `dom/security/nsContentSecurityManager.cpp` — added `yard` to scheme whitelist at line ~1025

**Patch files in repo:**
- `patches/yard-protocol-handler.patch` — new source files
- `patches/yard-protocol-registration.patch` — registration and security changes

**Key lessons learned:**
- Firefox 152 uses static components system (`components.conf`), not `nsNetModule.cpp`
- `FINAL_LIBRARY` must be `"xul-real"` not `"xul"` to link into the main binary
- `nsInputStreamChannel` lives in `mozilla::net` namespace
- Custom schemes must be added to the scheme whitelist in `nsContentSecurityManager.cpp` or content silently renders blank even when `NewChannel` succeeds
- Multi-process architecture: `NewChannel` runs in parent process; content renders in child — principal mismatches cause silent blank pages
- Debug with `MOZ_LOG="YardProtocol:5"` to confirm handler is being called

**Current behavior:**
- `yard://[peer-id]/[resource-type]/[resource-path]` renders a stub HTML page
- Shows parsed peer ID and path
- No DHT resolution yet — stub only
- Logging: `MOZ_LOG="YardProtocol:5"` shows channel creation in terminal

---

## Pending Milestones

### 🔲 Milestone 3 — Identity system (Chat 3)
Ed25519 key pair generation, peer ID derivation (first 8 hex chars of SHA-256 of public key), local encrypted storage with passphrase. No account recovery by design.

### 🔲 Milestone 4 — The Fence / Ledger (Chat 4)
Distributed append-only ledger. Whitelist governance, display name registry, bootstrap node list, council decisions.

### 🔲 Milestone 5 — The Porch / Forum (Chat 5)
Paginated forum renderer. Blue underlined links, arrow voting, 25 posts per page, no infinite scroll, no algorithmic feed.

### 🔲 Milestone 6 — The Shed / File sharing (Chat 6)
Encrypted peer-to-peer file transfer. Metadata indexed via DHT, content never stored on intermediary.

### 🔲 Milestone 7 — Peer discovery (Chat 7)
DHT routing, bootstrap nodes, sidecar daemon. This is what replaces the stub in the protocol handler.

---

## Architecture Notes

### Sidecar daemon (planned)
DHT/peer resolution will live in a separate local Rust process, not compiled into Gecko. The protocol handler will talk to it over a local socket. This keeps the iteration loop fast — daemon changes don't require a Gecko rebuild.

### Protocol handler is a stub
`NewChannel` currently returns hardcoded HTML. The peer ID and path are parsed correctly but not resolved. When the sidecar daemon exists, `NewChannel` will open a socket to it, pass the peer ID + resource type + path, and stream the response back as the channel content.

---

## Repo Layout (GitHub: Rock-Gungadee/theyard-browser)

```
patches/          — all source patches applied on top of Firefox 152.0.2
  yard-protocol-handler.patch       — new yard:// handler source files
  yard-protocol-registration.patch  — component registration + security whitelist
  [librewolf patches...]            — upstream LibreWolf patches
assets/           — mozconfig, Dockerfile, patch list
browser/          — browser-level customizations
themes/           — UI theme patches
settings/         — LibreWolf settings submodule
version           — 152.0.2
Makefile          — fetch / dir / bootstrap / build / package targets
```

---

## How to Start a New Build Session

```bash
# 1. Restore Hetzner snapshot in console
# 2. SSH in
ssh root@[hetzner-ip]

# 3. Ensure swap is active
swapon /swapfile

# 4. Pull latest changes
cd ~/theyard-browser && git pull

# 5. Apply any new patches to source tree
patch -p1 -d librewolf-152.0.2-1 < patches/your-new.patch

# 6. Build
make build 2>&1 | tee build.log

# 7. Check for errors
grep " E " build.log | grep -v "gmake\|Waiting"

# 8. Copy binary to Mac (run on Mac)
rsync -aL --info=progress2 root@[ip]:~/theyard-browser/librewolf-152.0.2-1/obj-x86_64-pc-linux-gnu/dist/bin/ ~/yard-bin-v2/

# 9. Copy to VM (run on Mac)
rsync -aL --info=progress2 ~/yard-bin-v2/ yard@192.168.64.6:~/librewolf/

# 10. Test on VM
cd ~/librewolf && MOZ_LOG="YardProtocol:5" ./librewolf "yard://a3f9bc12/forum/hello"

# 11. Snapshot and destroy server when done
```
