# Razor CUDA 2.4 — handoff for the next Grok session

**Do not overwrite** files at the root of `tmg270/Pub`
(`razor`, `razor.sh`, `razor.exe`, `ShearK-Miner`, `protected.c`, …).
This directory is additive.

## Where the source is

| Repo | Visibility | What |
|---|---|---|
| [tmg270/razor](https://github.com/tmg270/razor) | **private** | Full source. `main` @ `32db52c` = **2.4** |
| [tmg270/Pub](https://github.com/tmg270/Pub) | public | Distro binaries. **This folder** = CUDA 2.4 Windows zip/exe |
| [tmg270/leo](https://github.com/tmg270/leo) | private | Abandoned first GPU attempt. Ignore unless archaeology. |

There is **no Razor 2.3** on GitHub. Tags/branches/releases: none.
Latest CPU protocol on GH is **1.13** (stats-ACK ignore, no prefetch=mov).
2.0/2.4 version stamps were CUDA work bolted onto 1.13. If the user has 2.3
only on the 5950X, it was never pushed.

## What 2.4 actually is

ShearHash-v2 / RandomX-lite miner.

- **CPU path** is the 1.13 razor hot loop (jit-full, prefetch t0, 32 threads on 5950X ≈ 16 kH/s).
- **GPU path** (`--cuda`): device interpreter proposes candidates; **CPU `rx_hash` is the only submit authority**.
- 5% fee, second TCP connection, fee address XOR-encoded in `src/razor.h` (not plaintext `she1` in the PE).
- Windows PE loads `nvcuda.dll` at runtime (driver API). PTX is embedded (`src/gpu_ptx.c`, sm_75). No CUDA toolkit on the user’s box.

## Measured on the user’s 5950X + RTX 3080

- CPU `--threads 32` ≈ **16 kH/s** (16 threads was slower).
- GPU first launch was **256 hashes = 8 of 68 SMs** → dead-flat **128 H/s @ 37 W / vRel**.
- After occupancy fill (SMs × 32–64, 2 MiB scratchpad each) GPU ≈ **1.09 kH/s**.
- RandomX is L3-latency shaped. GDDR bandwidth does not beat 5950X L3. Optimized RandomX CUDA ceiling on a 3080 is ~1.5 kH/s (WhatToMine). Do not promise 16 kH from the GPU.

## HUD

`cpu 16.1 kH/s  gpu 1.09 kH/s  tot 17.2 kH/s`

`tot` **must** be `cpu + gpu`. Independent EMA of the combined counter hides 1 kH inside 16 kH.

## Files in this folder

- `razor.exe` — stripped Windows x64 2.4 (~1.2 MB uncompressed; zip looks ~317 KB because PTX is repetitive ASCII).
- `razor-windows-x64.zip` — exe + `mine-5950.bat` + `enable-huge.bat` + README.
- `mine-5950.bat` — `--threads 32 --no-tune --backend jit-full --prefetch t0 --cuda`

Selftest digest:

`64d41fa97f5ebea8a7e2a2625b1824467ce9d081bf29b0b2ae0a7fe617599895`

## Build (Linux sandbox with llvm-mingw)

```
cd razor
make -j4
./razor --selftest
make win
# artifact: build/win/razor.exe
```

`--cuda-batch N` overrides auto SM fill if VRAM OOMs.

## Do not

- Run two miner processes on one GPU (they split the 10 GB). Parallel copies are the grid, not two exes.
- Autotune prefetch=mov (invalid shares). 1.13 already capped prefetch trials to t0/nta.
- Treat stats JSON-RPC id=3 ACKs as share ACKs (`msgid != 0 && msgid != 2` → return).
- Overwrite Pub root `razor` / `razor.sh` (those are the CPU-only distro the user already had).
- Claim GPU “does hashes then CPU only submits” without the CPU re-hash. Device VM is an interpreter; CPU JIT is canonical.

## User

Joe / tmg270 / hayalexj. Pool `pool.shear.digital:1111`.
Login used on the 5950X: `she1q8qs265j8wsfhrtgtufgdfn780q377x65zawsz9.win5950`
Fee: 5% to XOR’d `she1qnna…` in `src/razor.h`.
Keyboard: UK layout, avoid `~` `" ` `@` in one-liners they have to paste.
