# 5G-AKA
Python implementation of the 5G AKA protocol with added ECISE SUCI encryption.

## Requirements

- Python 3.8

## Setup

Before starting the simulation, ensure you have the necessary libraries installed.

1. **Install dependencies:**

   ```shell
   pip install cryptography ecies bplib
   ```

2. **Running the simulation:**

   Start the components in the following order:

   - Home Network (HN):

     ```shell
     python home_network.py
     ```

   - Serving Network (SN):

     ```shell
     python serving_network.py
     ```

   - Subscriber (Sub):

     ```shell
     python subscriber.py
     ```

3. **Simulating re-synchronization:**

   Modify `sqn_ue` in `subscriber.py` and `sqn_hn` in `home_network.py` to ensure `sqn_ue >= sqn_hn`.

4. **Simulating MAC error:**

   Change `k = crypto.getKey()` to `k = crypto.getKey(True)` in either `home_network.py` or `subscriber.py` (only need to modify one).

## Code Overview

### `home_network.py`

This file defines the `HomeNetwork` class, which handles the core authentication logic.

#### Main Methods

- `connectSN()`: Connects to the Serving Network (SN) and performs authentication.
- `getSUPI()`: Decrypts the Subscriber Concealed Identifier (SUCI) to get the Subscriber Permanent Identifier (SUPI).
- `authentication_challenge()`: Generates a challenge for the authentication process.
- `verify()`: Verifies the authenticity of the received AUTS value.

### `serving_network.py`

This file defines the `ServingNetwork` class, which acts as an intermediary between the Subscriber and the Home Network.

#### Main Methods

- `connectHN(port_hn)`: Connects to the Home Network (HN).
- `transfer()`: Manages the data transfer between the Subscriber and the Home Network.

### `subscriber.py`

This file defines the `Subscriber` class, which represents the user trying to authenticate and connect to the network.

#### Main Methods

- `connectSN()`: Connects to the Serving Network (SN) and initiates the authentication process.
- `getSUCI()`: Encrypts the SUPI to generate the SUCI.
- `verify()`: Verifies the received AUTN value.
- `getRES_star()`: Generates the RES* value.
- `getAUTS()`: Generates the AUTS value.

---

By following the instructions above, you should be able to set up and run the authentication network simulation. If you encounter any issues or have questions, feel free to reach out or check the documentation of the respective libraries.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgements

Special thanks to the developers of the cryptographic libraries used in this project.
