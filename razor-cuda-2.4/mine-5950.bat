@echo off
rem 5950X: 32 threads (that's your 16 kH/s) + RTX 3080 RandomX lane
razor.exe --threads 32 --no-tune --backend jit-full --prefetch t0 --cuda --pool pool.shear.digital:1111 --user she1q8qs265j8wsfhrtgtufgdfn780q377x65zawsz9.win5950
pause
