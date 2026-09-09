@echo off
rem 5950X: 16 physical cores, jit-full, huge pages if enabled
razor.exe --threads 16 --no-tune --backend jit-full --prefetch t0 --pool pool.shear.digital:1111 --user she1q8qs265j8wsfhrtgtufgdfn780q377x65zawsz9.win5950
pause
