# AAKA+ Implementations
Python implementation of the AAKA(Anonymous Authentication and Key Agreement)+BB(boneh-Boyen signature)/PS(Pointcheval-Sanders Signature) schemes.

## Requirements

- Python 3.8

## Setup

Before starting the simulations, ensure you have the necessary libraries installed.

1. **Install dependencies:**

   ```shell
   pip install cryptography ecies bplib pytest
   ```

## Running the Simulations

### AAKA+BB Scheme

1. **Class**:

   ```shell
   python aaka_bb.py
   ```

2. **Testing AAKA+BB**:

   ```shell
   python -m pytest test_aaka_bb.py
   ```

3. **Performance Testing AAKA+BB**:

   ```shell
   python time_aaka_bb.py
   ```

### AAKA with PS Scheme

1. **Class**:

   ```shell
   python aaka_ps.py
   ```

2. **Testing AAKA+PS**:

   ```shell
   python -m pytest test_aaka_ps.py
   ```

3. **Performance Testing AAKA+PS**:

   ```shell
   python time_aaka_ps.py
   ```

## Code Overview

### Specific to AAKA+ Scheme (`aaka_bb.py`, `aaka_ps.py`)

This file defines the `AAKA+` class, which handles the AAKA+BB/PS schemes logic.

#### Main Methods

- `IKeyGen(q)`: Generate issuer key pair.
- `LEAKeyGen()`: Generate LEA key pair.
- `AsymKeyGen()`: Generate asymmetric key pair.
- `CredIssue(isk, ipk, m, pm)`: Issue a credential.
- `CredVer(ipk, m, pm, cred, pi)`: Verify a credential.
- `KeyExchange_UE()`: Perform user equipment key exchange.
- `KeyExchange_XN(A, Y, y)`: Perform XN key exchange.
- `KeyExchange_UE_Ver(Y, A, B, a, tau)`: Verify user equipment key exchange.
- `CredShow(ipk, tpk, m, pm, cred, keyEx)`: Show a credential.
- `AcredVer(ipk, tpk, m, Acred, pi, keyEx)`: Verify an anonymous credential.
- `Trace(tsk, Acred)`: Trace an anonymous credential.
- `judge(Acred, RL)`: Judge if a user is revoked.

## Running on Different Platforms

These scripts are designed to run on both Linux and Windows systems. Ensure you have Python and the required libraries installed, and follow the instructions for running each script as described above.


## Acknowledgements

Special thanks to the developers of the cryptographic libraries used in this project.
