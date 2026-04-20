# Paper Sweep Summary

## Threshold

| batch | mode | runs | exec tfhe mean (ms) | prover mean (ms) | verifier mean (ms) | verify_tfhe mean (us) | proof mean (MiB) | comm mean (KiB) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | orhe | 1 | 8,282.016 | 761.321 | 98.311 | 0.000 | 4.396 | 4,506.324 |
| 1 | plain_tfhe | 1 | 8,327.415 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |

## Derived

| member | runs | arity | lin | pbs | depth | tfhe mean (ms) | prover mean (ms) | verifier mean (ms) | proof mean (KiB) | comm mean (KiB) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| f1 | 1 | 1 | 1 | 1 | 1 | 1,925.426 | 624.191 | 2,281.163 | 127.508 | 226.469 |
| f2 | 1 | 1 | 2 | 1 | 1 | 3,023.948 | 559.164 | 2,923.761 | 127.508 | 266.031 |
| f3 | 1 | 1 | 2 | 2 | 2 | 2,976.372 | 1,289.688 | 3,411.087 | 255.016 | 413.320 |
| f4 | 1 | 2 | 1 | 1 | 1 | 4,015.092 | 530.634 | 4,297.680 | 127.508 | 266.078 |
| f5 | 1 | 2 | 2 | 1 | 1 | 4,610.442 | 511.960 | 4,781.432 | 127.508 | 305.641 |
| f6 | 1 | 2 | 3 | 2 | 2 | 4,438.306 | 1,235.384 | 3,998.850 | 255.016 | 492.492 |

## Checks

- All aggregation checks passed.
