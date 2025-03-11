# Verifiable_Mixnet_for_Voting

**Final project for Applied Cryptography Workshop, supervisor: Prof. Tal Moran, Reichman University**

**Project by: Guy Gal, Itzik Baruch, Idan Refaeli**

This project implements a verifiable mixnet voting system built on Abe's protocol with enhanced cryptographic verification. It provides a secure, private, and publicly verifiable voting solution where encrypted ballots are shuffled and tallied without compromising voter anonymity.

## OVERVIEW

The system achieves:
- **Privacy** – Votes remain completely anonymous throughout the process.
- **Security** – Ballots are encrypted using robust EC-ElGamal encryption, preventing tampering. (A voter cannot prove his vote.)
- **Integrity** – Every vote is accurately recorded and counted, ensuring that the final tally is correct.
- **Transparency** – Encrypted votes, mix batch outputs, and cryptographic proofs (including zero-knowledge proofs) are published on a bulletin board for independent verification.

The mixnet uses a permutation network (based on the Waksman algorithm) to randomly reorder ballots. It employs zero-knowledge proofs (OR-proofs composed of two AND-proofs, each with two Schnorr discrete-log proofs using the Fiat–Shamir heuristic) to verify that votes are correctly switched without revealing vote identities. Threshold decryption is used to distribute trust among multiple servers, ensuring no single entity can decrypt votes alone.

## PROJECT ARCHITECTURE

### Frontend: Voting & Encrypting
- **User Interface** – Built with ReactJS, it allows voters to submit ballots and view the election status.
- **Client-Side Encryption** – Votes are encrypted in the browser using EC-ElGamal before transmission (assuming an honest browser).

### Backend Components

#### Bulletin Board:
- **Data Hub** – Stores encrypted votes, public keys, mix batch outputs, and ZKPs. Each user can retrieve their signed encrypted vote.
- **Signed Data** – Every post is signed using Ed25519 (an elliptic curve signature scheme) to ensure authenticity.
- **Aggregation & Verification** – Final results and verification status are published for independent verification.

#### Mixnet:
- **Mix Servers** – A network of servers run a permutation network to shuffle votes using random permutations, ensuring no link between input and output. Each server uses a matrix of switches to route and re-encrypt votes.
- **Zero-Knowledge Proofs** – Each shuffle is proven correct using an OR-proof (made up of two AND-proofs with Schnorr proofs), without revealing the switch configuration.
- **Threshold Decryption** – Multiple servers collaborate using a t-out-of-n scheme (via Shamir's secret sharing with a random polynomial of degree t–1) to decrypt the final tally. This ensures that no single server can decrypt votes alone.

#### Pre-process: Key Generation
- **Threshold Scheme** – Private key shares are distributed among multiple servers; no single server holds the entire decryption key.

## DETAILED SYSTEM FLOW

1. **Public Key Distribution**:
   - The client retrieves the public key from the bulletin board.
   - The public key is stored in hexadecimal format, with RSA-2048 used for signing in the Node backend.

2. **Encryption**:
   - The client encrypts the vote using EC-ElGamal. A mapping from vote choices (e.g., "1", "2", …) to EC points is used.
   - Rerandomization is applied to ensure that even identical votes produce unlinkable ciphertexts.

3. **Bulletin Board & Vote Submission**:
   - Encrypted votes are posted to the bulletin board.
   - Each vote is signed and stored, ensuring authenticity and integrity.

4. **Mixing (Shuffling)**:
   - Mix servers retrieve votes and process them through a permutation network.
   - Each server sets its switches (either straight or cross) according to a random permutation and re-encrypts the votes.
   - Zero-knowledge proofs are generated to prove correct shuffling without revealing the permutation.

5. **Decryption & Verification**:
   - Once mixing is complete, threshold decryption is initiated.
   - A subset of servers collaborates to decrypt the final tally.
   - An all-steps verifier confirms that each mix and decryption step was performed correctly by checking signatures and ZKPs.
   - Final results are published for public verification.

## PROJECT STRUCTURE

### Mixnet Core (org.example.mixnet):
- **Mixing Components**:
  - `MixServer.js` & `MixServersManager.js` (or their Kotlin equivalents): Manage mix servers and the mixing process.
  - `PermutationNetwork.js`: Implements recursive vote mixing using the Waksman algorithm.
  - `Switch.js` & `SwitchPost.js`: Define 2×2 switch operations with rerandomization and ZKP generation.
- **Vote Handling**:
  - `Vote.js`: Represents individual encrypted votes.
  - `MixBatchOutput.js`: Encapsulates mixed vote batches.
- **Zero-Knowledge Proofs & Verification**:
  - `ZKPUtils.js` and `ZKProofDataclasses.js`: Generate and manage ZKPs.
  - `Verifier.js`: Verifies mix batch outputs and proofs.

### Cryptographic Utilities (org.example.crypto):
- **Encryption & Rerandomization**:
  - `Elgamal.js`: Implements EC-ElGamal encryption, decryption, and rerandomization.
- **Utilities & Key Serialization**:
  - `CryptoUtils.js`: Provides methods for EC point serialization/deserialization and hashing.
  - `KeySerialization.js`: Converts keys to/from protocol buffer messages.
  - `MessageUtils.js`: Converts between strings and ECPoints.
- **Configuration**:
  - `CryptoConfig.js` & `CryptoConfigThreshold.js`: Set up elliptic curve parameters and threshold decryption.
- **Digital Signatures**:
  - `Ed25519Utils.js`: Signs and verifies mix batch outputs.

### Bulletin Board Components (bulltinboard / org.example.bulltinboard):
- **Data Structures**:
  - `BulletinBoardMixBatchOutput.js` & `BulletinBoardVote.js`: Define formats for mix batch outputs and votes.
- **Communication & Testing**:
  - `BulletinBoard.js`: Provides an HTTP API for publishing and retrieving data.
  - `BulltinBoardTesting.js`: Demo routines for testing bulletin board operations.
  - `PublicKeyData.js`: Structures for transmitting public key data.

### Build Configuration:
- Uses Gradle with Kotlin DSL for the cryptographic system and Node.js (with Express) for the bulletin board service.
- Frontend built with React (App.js, index.js, etc.) with accompanying CSS files.

## MIXNET VOTING APPLICATION (NODE BACKEND)

### Run Locally:
1. Install Node.js 16 (nvm is recommended for version management).
2. Create an .env file in the root directory (refer to env-example.txt for required variables).
3. Run "npm install" to install dependencies.
4. Run "npm run dev" to start the service.
5. The service runs on port 3000.

### Notes:
- Ensure a "certs" folder exists in the root directory containing "private.pem" and "public.pem" (RSA-2048 key pair).

A Postman collection is available for API testing at:
https://www.postman.com/supply-astronomer-70090851/workspace/mixnet/collection/28881760-28788f6e-7f13-47e5-8b2f-9f83c5a10abf?action=share&creator=28881760

## PREREQUISITES

- JDK 11 or later
- Kotlin 1.5+
- Gradle
- Bouncy Castle (for cryptographic operations)
- Ktor Client (for HTTP communication)
- Node.js 16 for the backend service

## INSTALLATION & BUILD

### For the Cryptographic Mixnet System:
1. Clone the repository:
   ```
   git clone https://github.com/yourusername/secure-mixnet-voting.git
   cd secure-mixnet-voting
   ```
2. Build the project using Gradle:
   ```
   ./gradlew build
   ```
3. Run tests (if applicable):
   ```
   ./gradlew test
   ```

### For the Node Backend (Mixnet Voting Application):
1. In the repository root, run:
   ```
   npm install
   ```
2. Start the service:
   ```
   npm run dev
   ```

## CONFIGURATION

- **Elliptic Curve Settings**:
  The default curve is secp256r1 (configured in CryptoConfig.js).

- **Threshold Decryption**:
  Adjust the number of servers (n) and the threshold (t) as needed in the bulletin board and threshold modules.

- **Bulletin Board API**:
  Update the base URL in BulletinBoard.js to match your deployment.

## ACKNOWLEDGEMENTS

- **Bouncy Castle** – For robust cryptographic implementations.
- **Ktor** – For HTTP client support.
- **KotlinX Libraries** – For serialization and coroutine support.
- **Express, MongoDB, and related Node.js libraries** – For building the backend service.

## PRESENTATION

For an updated overview of the project, refer to the Presentation.pdf file provided.

Happy voting and secure elections!
