#!/bin/sh
exec ./razor --threads 8 --no-tune --prefetch t0 --backend jit-full --pool pool.shear.digital:1111 --user she1q8qs265j8wsfhrtgtufgdfn780q377x65zawsz9.vm "$@"
