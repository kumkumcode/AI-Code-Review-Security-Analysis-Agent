# random — Generate pseudo-random numbers

## Overview

The `random` module is used to generate pseudo-random numbers for different purposes like:
- Generating random integers and floats
- Selecting random elements from sequences
- Shuffling lists
- Creating random samples
- Generating probability distributions

Python uses the **Mersenne Twister** algorithm as the core random number generator.

Note:
- It is fast and thread-safe.
- It is deterministic, meaning the same seed produces the same sequence.
- It is **not suitable for cryptographic purposes**.
- For security-related random values, use the `secrets` module.

---

## Import random module

```python
import random