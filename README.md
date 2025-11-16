# HDcrypt

HDcrypt is a small command-line tool for encrypting and decrypting files using OpenPGP (PGP) with either a password (symmetric encryption) or public/private keys (asymmetric encryption). It can also generate a new RSA key pair for use with key-based encryption.

Features
- Symmetric (password-based) encryption and decryption
- Asymmetric (public/private key) encryption and decryption
- RSA key pair generation (4096-bit)
- Optional ASCII armor output for encrypted files
- Selectable compression algorithm (ZIP, ZLIB, BZIP2, NONE)
- Integrity protection (MDC) enabled by default

Requirements
- .NET SDK 10 (C# 14.0)
- BouncyCastle (bundled by the project)

Build
- Using .NET CLI:
  - dotnet build
- Using Visual Studio:
  - Open the solution, select the `HDcrypt` project, and build the solution.

Quick start
- Show help:
  - HDcrypt.exe -h

- Encrypt with password (binary output):
  - HDcrypt.exe -e -p mypass -i input.bin -o output.pgp

- Encrypt with password and ASCII armor:
  - HDcrypt.exe -e -p mypass -i input.bin -o output.asc -a

- Decrypt with password:
  - HDcrypt.exe -d -p mypass -i output.pgp -o input.bin

- Generate a key pair (public/private):
  - HDcrypt.exe -g user@example.com -o mykey
  - Produces: mykey-public.asc and mykey-private.asc

- Encrypt with a public key:
  - HDcrypt.exe -e -k mykey-public.asc -i input.bin -o output.pgp -a

- Decrypt with a private key:
  - HDcrypt.exe -d -k mykey-private.asc -i output.pgp -o input.bin
  - If your private key is protected with a passphrase (not applied in current version), add -p <passphrase>

Usage
- Symmetric (password):
  - HDcrypt.exe -e -p <password> -i <input> -o <output> [options]
  - HDcrypt.exe -d -p <password> -i <input> -o <output> [options]

- Asymmetric (keys):
  - HDcrypt.exe -e -k <publickey.asc> -i <input> -o <output> [options]
  - HDcrypt.exe -d -k <privatekey.asc> [-p <passphrase>] -i <input> -o <output> [options]

- Key generation:
  - HDcrypt.exe -g <userId/email> -o <prefix> [-p <passphrase>]

Options
- -a
  - When encrypting, write ASCII-armored output (text format: .asc)
- -k <key file>
  - Path to key file
  - For encryption: public key file
  - For decryption: private key file
- -g <userId/email>
  - Generate a new RSA key pair using the given user ID (e.g., email)
  - Requires -o to specify the output prefix
- -p <password|passphrase>
  - For symmetric mode: the password used to encrypt/decrypt
  - For key mode (decrypt): passphrase for the private key (if protected)
  - For key generation: intended as a key passphrase (not applied in current version)
- -c <ZIP|ZLIB|BZIP2|NONE>
  - Compression algorithm used inside the PGP container (default: ZIP)
- --overwrite
  - Overwrite the output file if it exists
- --no-integrity
  - Disable integrity protection (MDC)
- -h | --help
  - Show usage information

Details
- Symmetric encryption uses AES-256 with integrity protection (MDC) by default.
- In symmetric mode, the password is added with SHA1 as required by PGP for PBE parameters.
- In key mode, encryption uses the provided public key; decryption uses the matching private key.
- ASCII armor (-a) produces text output (.asc). Without -a, output is binary (.pgp).
- Compression applies to the literal data before encryption (ZIP default). Use NONE to disable.

Key generation
- Generates a 4096-bit RSA key pair and writes two files:
  - <prefix>-public.asc
  - <prefix>-private.asc
- Current version note: the generated private key is not protected with a passphrase (unencrypted). The -p argument is accepted but not applied yet.
- Recommendation: protect and store your private key securely. If passphrase protection is required, keep private key access restricted or add protection with an external tool until passphrase support is implemented here.

Exit codes
- 0  success
- 1  invalid arguments (usage error)
- 2  input file not found
- 3  output file exists without --overwrite
- -1 runtime error (see error message)

Examples
- Encrypt a PDF with a public key, ASCII armored, override output if exists:
  - HDcrypt.exe -e -k friend-public.asc -i report.pdf -o report.pdf.asc -a --overwrite

- Decrypt an armored message with password and write the original file:
  - HDcrypt.exe -d -p s3cret -i secret.asc -o original.bin

- Use BZIP2 compression for better ratio:
  - HDcrypt.exe -e -p s3cret -i data.csv -o data.csv.pgp -c BZIP2

- Disable integrity protection (not recommended):
  - HDcrypt.exe -e -p s3cret -i data.bin -o data.bin.pgp --no-integrity

Compatibility
- HDcrypt produces/consumes data compatible with OpenPGP tools that support:
  - AES-256, MDC, ZIP/ZLIB/BZIP2 compression
  - ASCII armor for armored outputs
  - Public-key encrypted session for RSA keys
- For symmetric encryption, ensure the consuming tool supports PBE with MDC.

Troubleshooting
- Output file exists
  - Add --overwrite to replace the file
- Wrong password or key
  - Decryption fails with integrity check error; verify the password or use the correct key
- Bad PGP data
  - Ensure the input file is a valid PGP message (binary or ASCII armored)
- Key mismatch
  - Ensure the private key corresponds to the public key used for encryption

Security notes
- Keep private keys and passwords secure. Do not commit them to source control.
- Prefer keeping integrity protection enabled (default).
- Consider using armor for portable text-based transport, but prefer binary for efficiency.

License
- See repository license if provided.

Acknowledgements
- Built on BouncyCastle for OpenPGP support.
