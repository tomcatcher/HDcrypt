// HDcrypt file encryptor/decryptor by Tomas Tudja @ H-DCS
// This tool either encrypts, decrypts files, or generates key pairs using PGP encryption.
// Usage:
//   Encrypt/Decrypt (password): HDcrypt.exe -e|-d -p <password> -i <input file> -o <output file>
//   Encrypt/Decrypt (keys):     HDcrypt.exe -e|-d -k <key file> [-p <passphrase>] -i <input file> -o <output file>
//   Generate key pair:          HDcrypt.exe -g <userId/email> -o <output prefix> [-p <passphrase>""]

using System;
using System.IO;
using Org.BouncyCastle.Bcpg;

namespace HDcrypt
{
    class Program
    {
        static int Main(string[] args)
        {
            try
            {
                if (args.Length == 0)
                {
                    PrintUsage();
                    return 1;
                }

                bool encrypt = false;
                bool decrypt = false;
                bool armor = false;
                bool overwrite = false;
                bool withIntegrity = true;
                string? compressionStr = "ZIP"; // default
                string? password = null; // password or key passphrase (captured interactively)
                string? inputFile = null;
                string? outputFile = null; // output file for encrypt/decrypt; prefix for key generation
                string? keyFile = null; // key file (public for encryption, private for decryption)
                string? generateUserId = null; // user id (email) for key generation
                bool promptPassword = false; // whether to ask interactively

                for (int i = 0; i < args.Length; i++)
                {
                    switch (args[i])
                    {
                        case "-e":
                            encrypt = true;
                            break;
                        case "-d":
                            decrypt = true;
                            break;
                        case "-p":
                            // Interactive password/passphrase prompt (no value consumed)
                            promptPassword = true;
                            break;
                        case "-k":
                            if (i + 1 < args.Length) keyFile = args[++i];
                            break;
                        case "-i":
                            if (i + 1 < args.Length) inputFile = args[++i];
                            break;
                        case "-o":
                            if (i + 1 < args.Length) outputFile = args[++i];
                            break;
                        case "-a":
                            armor = true;
                            break;
                        case "-c":
                            if (i + 1 < args.Length) compressionStr = args[++i];
                            break;
                        case "--overwrite":
                            overwrite = true;
                            break;
                        case "--no-integrity":
                            withIntegrity = false;
                            break;
                        case "-g":
                            if (i + 1 < args.Length) generateUserId = args[++i];
                            break;
                        case "-h":
                        case "--help":
                            PrintUsage();
                            return 0;
                    }
                }

                bool generationMode = !string.IsNullOrEmpty(generateUserId);
                bool keyMode = !string.IsNullOrEmpty(keyFile);

                // Prompt for password/passphrase if requested
                if (promptPassword)
                {
                    string prompt = generationMode
                        ? "Enter passphrase (leave empty for none): "
                        : keyMode && decrypt
                            ? "Enter private key passphrase (leave empty if none): "
                            : keyMode && encrypt
                                ? "Enter private key protection passphrase (leave empty if none): "
                                : "Enter password: ";
                    password = ReadHiddenInput(prompt, allowEmpty: generationMode || keyMode);
                }

                // Validate mode combinations
                if (generationMode && (encrypt || decrypt))
                {
                    Console.Error.WriteLine("Cannot combine -g with -e or -d. Key generation is a separate mode.\n");
                    PrintUsage();
                    return 1;
                }

                if (generationMode)
                {
                    if (string.IsNullOrEmpty(outputFile))
                    {
                        Console.Error.WriteLine("Output prefix (-o <prefix>) is required for key generation.\n");
                        PrintUsage();
                        return 1;
                    }

                    Console.WriteLine($"Generating PGP key pair for '{generateUserId}' (passphrase {(string.IsNullOrEmpty(password) ? "<none>" : "provided")})...");
                    var result = PgpKeyGenerator.GenerateKeyPair(generateUserId!, outputFile!, password);
                    Console.WriteLine("Key pair generated:");
                    Console.WriteLine($"  Public key : {result.PublicKeyPath}");
                    Console.WriteLine($"  Private key: {result.PrivateKeyPath}");
                    return 0;
                }

                // Validate basic operation flags for encrypt/decrypt
                if ((encrypt && decrypt) || (!encrypt && !decrypt) || string.IsNullOrEmpty(inputFile) || string.IsNullOrEmpty(outputFile))
                {
                    PrintUsage();
                    return 1;
                }

                if (!File.Exists(inputFile))
                {
                    Console.Error.WriteLine($"Input file not found: {inputFile}");
                    return 2;
                }

                if (File.Exists(outputFile) && !overwrite)
                {
                    Console.Error.WriteLine($"Output file already exists: {outputFile}. Use --overwrite to replace.");
                    return 3;
                }

                // For password-based (no key file) operations, password required
                if (!keyMode && string.IsNullOrEmpty(password))
                {
                    Console.Error.WriteLine("Password required. Use -p to enter it interactively.\n");
                    PrintUsage();
                    return 1;
                }

                var compression = ParseCompression(compressionStr);

                if (encrypt)
                {
                    if (keyMode)
                    {
                        Console.WriteLine($"Encrypting {inputFile} -> {outputFile} using public key '{keyFile}' (armor={armor}, integrity={withIntegrity}, compression={compression})");
                        PgpKeyEncryptor.EncryptFileWithPublicKey(inputFile!, outputFile!, keyFile!, armor, withIntegrity, compression);
                    }
                    else
                    {
                        Console.WriteLine($"Encrypting {inputFile} -> {outputFile} using password (armor={armor}, integrity={withIntegrity}, compression={compression})");
                        PgpPasswordEncryptor.EncryptFile(inputFile!, outputFile!, password!, armor, withIntegrity, compression);
                    }
                }
                else
                {
                    if (keyMode)
                    {
                        Console.WriteLine($"Decrypting {inputFile} -> {outputFile} using private key '{keyFile}'");
                        PgpKeyEncryptor.DecryptFileWithPrivateKey(inputFile!, outputFile!, keyFile!, password);
                    }
                    else
                    {
                        Console.WriteLine($"Decrypting {inputFile} -> {outputFile} using password");
                        PgpPasswordEncryptor.DecryptFile(inputFile!, outputFile!, password!);
                    }
                }

                Console.WriteLine("Done.");
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
#if DEBUG
                Console.Error.WriteLine(ex);
#endif
                return -1;
            }
        }

        static CompressionAlgorithmTag ParseCompression(string? value)
        {
            if (string.IsNullOrWhiteSpace(value)) return CompressionAlgorithmTag.Zip;
            switch (value.Trim().ToUpperInvariant())
            {
                case "ZIP":
                    return CompressionAlgorithmTag.Zip;
                case "ZLIB":
                    return CompressionAlgorithmTag.ZLib;
                case "BZIP2":
                case "BZIP":
                    return CompressionAlgorithmTag.BZip2;
                case "UNCOMPRESSED":
                case "NONE":
                    return CompressionAlgorithmTag.Uncompressed;
                default:
                    throw new ArgumentException($"Unknown compression algorithm: {value}. Use ZIP, ZLIB, BZIP2, or NONE.");
            }
        }

        static void PrintUsage()
        {
            Console.WriteLine(
                "HDcrypt file encryptor/decryptor/key generator by Tomas Tudja @ H-DCS\r\n" +
                "This tool can encrypt, decrypt files, or generate PGP key pairs.\r\n" +
                "Password-based (symmetric) and public/private key encryption supported.\r\n" +
                "Usage:\r\n" +
                "  Encrypt (password): HDcrypt.exe -e -p -i <input> -o <output> [options]\r\n" +
                "  Decrypt (password): HDcrypt.exe -d -p -i <input> -o <output> [options]\r\n" +
                "  Encrypt (key):      HDcrypt.exe -e -k <publickey.asc> [-p] -i <input> -o <output> [options]\r\n" +
                "  Decrypt (key):      HDcrypt.exe -d -k <privatekey.asc> [-p] -i <input> -o <output> [options]\r\n" +
                "  Generate keys:      HDcrypt.exe -g <userId/email> -o <prefix> [-p]\r\n" +
                "\r\nOptions:\r\n" +
                "  -a                         Output ASCII armor (encryption only)\r\n" +
                "  -k <key file>              Key file (public for -e, private for -d)\r\n" +
                "  -g <userId/email>          Generate a new key pair (requires -o prefix)\r\n" +
                "  -p                         Prompt for password / passphrase securely (no echo)\r\n" +
                "  -c <ZIP|ZLIB|BZIP2|NONE>   Compression algorithm (default: ZIP)\r\n" +
                "  --overwrite                Overwrite output file if it exists (encrypt/decrypt)\r\n" +
                "  --no-integrity             Disable integrity protection (MDC)\r\n" +
                "  -h|--help                  Show this help\r\n" +
                "\r\nNotes:\r\n" +
                "  - Password is required for symmetric encryption/decryption; -p triggers interactive hidden entry.\r\n" +
                "  - Key generation passphrase optional; use -p to set one (leave blank for none).\r\n" +
                "  - Private key decryption passphrase optional; use -p to enter if needed.\r\n");
        }

        static string? ReadHiddenInput(string prompt, bool allowEmpty)
        {
            Console.Write(prompt);
            var chars = new System.Collections.Generic.List<char>();
            while (true)
            {
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Enter)
                {
                    Console.WriteLine();
                    if (!allowEmpty && chars.Count == 0)
                    {
                        Console.WriteLine("Value cannot be empty.");
                        Console.Write(prompt);
                        continue;
                    }
                    break;
                }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (chars.Count > 0) chars.RemoveAt(chars.Count - 1);
                    continue;
                }
                if (!char.IsControl(key.KeyChar))
                {
                    chars.Add(key.KeyChar);
                }
            }
            return chars.Count == 0 ? null : new string(chars.ToArray());
        }
    }
}