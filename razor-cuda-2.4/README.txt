Razor 2.0 Windows x64 — ShearHash-v2
5950X + RTX 3080

--threads 32 is the 16 kH/s you already have. --cuda fills the 3080.

Old build launched 256 hashes (8 of 68 SMs) → a dead-flat 128 H/s at ~37 W
and GPU-Z vRel (clocks parked). This build sizes parallel hashes to the SM
count (~2176–4352 on a 3080, ~4–8 GiB scratchpads). Do NOT run two copies;
one process already runs thousands of hashes in parallel.

RandomX is L3-latency shaped. GDDR is high bandwidth, high latency, tiny L2.
CPU 16 kH/s will stay the main engine; GPU is extra. Tune with --cuda-batch N.

1. enable-huge.bat as Administrator once, SIGN OUT, sign in.
2. Double-click mine-5950.bat

Selftest: razor.exe --selftest
Digest: 64d41fa97f5ebea8a7e2a2625b1824467ce9d081bf29b0b2ae0a7fe617599895
