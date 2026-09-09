@echo off
rem 5950X CPU 16 threads + RTX 3080 RandomX lane
rem GPU proposes share candidates; CPU RandomX re-hashes then submit (5% fee)
razor.exe --threads 16 --no-tune --backend jit-full --prefetch t0 --cuda --pool pool.shear.digital:1111 --user she1q8qs265j8wsfhrtgtufgdfn780q377x65zawsz9.win5950
pause
