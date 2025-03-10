# Secure Mixnet Voting System

**Final project for Applied Cryptography Workshop, supervisor: Prof. Tal Moran, Reichman University**

**Project by: Guy Gal, Itzik Baruch, Idan Refaeli**

A verifiable mixnet voting system built on Abe's protocol with enhanced cryptographic verification. This project provides a secure, private, and publicly verifiable voting solution where encrypted ballots are shuffled and tallied without compromising voter anonymity.

## Overview

The system achieves:
- **Privacy**: Votes remain completely anonymous throughout the process.
- **Security**: Ballots are encrypted using robust EC-ElGamal encryption, making tampering nearly impossible.
- **Integrity**: Every vote is accurately recorded and counted, ensuring that the final tally is correct.
- **Transparency**: The system publishes encrypted votes, mix batch outputs, and proofs on a bulletin board for independent verification.

The mixnet leverages a permutation network (based on the Waksman algorithm) to randomly reorder ballots, employs zero-knowledge proofs (ZKP) to verify shuffle correctness without revealing vote identities, and uses threshold decryption to distribute trust among multiple servers.

## Project Architecture

### Frontend: Voting & Encrypting
- **User Interface**: Developed using ReactJS, the UI allows voters to submit ballots and see the election status.
- **Client-Side Encryption**: Votes are encrypted in the browser using EC-ElGamal to ensure privacy before being transmitted.

### Backend Components

#### Bulletin Board:
- **Data Hub**: Acts as a repository for encrypted votes, public keys, and mix batch outputs.
- **Signed Data**: All published data is signed to guarantee authenticity.
- **Aggregation**: Final votes and proofs are aggregated for public verifiability.

#### Mixnet:
- **Mix Servers**: A set of servers run a permutation network that shuffles votes using random permutations ensuring no linkability between input and output.
- **Zero-Knowledge Proofs**: For every mix operation, ZKPs are generated and verified so that anyone can confirm the correctness of the shuffling process.
- **Threshold Decryption**: A t-out-of-n scheme ensures that decryption is only possible when a sufficient subset of servers collaborate, preventing any single server from compromising voter privacy.

#### Pre-process: Key Generation
- **Threshold Scheme**: Private key shares are distributed among multiple servers using a random polynomial of degree (t – 1). No single server holds the entire decryption key.

## Key Features

- **Mixnet Shuffling**: Randomly permutes ballots so that every possible ordering is equally likely.
- **Rerandomization**: Each ciphertext is rerandomized, ensuring that even duplicate votes cannot be linked.
- **Robust Encryption**: Uses EC-ElGamal with strong parameters to secure votes.
- **Independent Verification**: Anyone can verify the shuffles and partial decryptions, ensuring public confidence in the process.
- **Real-Time Visualization**: A user interface continuously retrieves and displays mixnet outputs and proofs.

## Project Structure

### Mixnet Core (`org.example.mixnet`):
- **Mixing Components**: Implements mix servers, permutation networks, switches, and verifiers.
  - `MixServer.kt` & `MixServersManager.kt`: Manage the mix servers and orchestrate the mixing process.
  - `PermutationNetwork.kt`: Implements the recursive vote mixing using the Waksman algorithm.
  - `Switch.kt` & `SwitchPost.kt`: Define 2×2 switch operations with rerandomization and ZKP generation.
- **Vote Handling**:
  - `Vote.kt`: Represents individual encrypted votes.
  - `MixBatchOutput.kt`: Encapsulates mixed vote batches.
- **Zero-Knowledge Proofs & Verification**:
  - `ZKPUtils.kt` and `ZKProofDataclasses.kt`: Generate and manage ZKPs.
  - `Verifier.kt`: Verifies mix batch outputs and proofs.

### Cryptographic Utilities (`org.example.crypto`):
- **Encryption & Rerandomization**:
  - `ElGamal.kt`: Implements EC-ElGamal encryption, decryption, and ciphertext rerandomization.
- **Utilities & Key Serialization**:
  - `CryptoUtils.kt`: Utilities for EC point serialization/deserialization and hashing.
  - `KeySerialization.kt`: Converts keys to/from protocol buffer messages.
  - `MessageUtils.kt`: Converts between strings and ECPoints.
- **Configuration**:
  - `CryptoConfig.kt`: Sets up elliptic curve parameters and handles key generation.
  - `CryptoConfigThreshold.kt`: Provides threshold decryption functionality.
- **Digital Signatures**:
  - `Ed25519Utils.kt`: Signs and verifies mix batch outputs.

### Bulletin Board Components (`bulltinboard` / `org.example.bulltinboard`):
- **Data Structures**:
  - `BulletinBoardMixBatchOutput.kt` & `BulletinBoardVote.kt`: Define serializable formats for mix batch outputs and votes.
- **Communication & Testing**:
  - `BulletinBoard.kt`: HTTP-based API for publishing and retrieving data.
  - `BulltinBoardTesting.kt`: Demo routines for testing bulletin board operations.
  - `PublicKeyData.kt`: Structures for transmitting public key data.

### Demo Application:
- **Main Application**:
  - `Main.kt`: Demonstrates key generation, encryption, rerandomization, decryption, and bulletin board interactions.

### Build Configuration:
- Uses Gradle with Kotlin DSL (see `gradle.properties`, `settings.gradle.kts`, and `build.gradle.kts`).

## Prerequisites

- JDK 11 or later
- Kotlin 1.5+
- Gradle
- Bouncy Castle (for cryptographic operations)
- Ktor Client (for HTTP communication with the bulletin board API)

## Installation & Build

1. **Clone the Repository**:

   ```
   git clone https://github.com/yourusername/secure-mixnet-voting.git
   cd secure-mixnet-voting
   ```

2. **Build the Project**:
   
   Use Gradle to build:

   ```
   ./gradlew build
   ```


## Configuration

- **Elliptic Curve Settings**:
  The default curve is secp256r1 (configured in `CryptoConfig.kt`).
  
- **Threshold Decryption**:
  Adjust the number of servers (n) and the threshold (t) in the bulletin board and threshold modules as needed.
  
- **Bulletin Board API**:
  Update the base URL in `BulletinBoard.kt` to match your bulletin board service.


## Acknowledgements

- **Bouncy Castle**: For providing robust cryptographic implementations.
- **Ktor**: For HTTP client support.
- **KotlinX Libraries**: For serialization and coroutine support.

## Presentation

For a quick overview, refer to the Presentation.pdf which summarizes:
- **Project Objectives**: Privacy, Security, Integrity, and Transparency.
- **System Architecture**:
  - Frontend for voting and encrypting ballots.
  - Backend bulletin board for storing and aggregating data.
  - Mixnet for shuffling and verifying votes.
  - Threshold decryption ensuring distributed trust.
- **Key Benefits**:
  - Mixnet shuffling for random ballot ordering.
  - Rerandomization to ensure unique ciphertexts.
  - Public verifiability through ZKPs and bulletin board posts.

Happy voting and secure elections!
