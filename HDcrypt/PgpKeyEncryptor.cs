using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace HDcrypt
{
    public static class PgpKeyEncryptor
    {
        private const int BufferSize = 1 << 16; // 64KB

        public static void EncryptFileWithPublicKey(string inputPath, string outputPath, string publicKeyPath, bool armor, bool withIntegrity, CompressionAlgorithmTag compression)
        {
            if (string.IsNullOrWhiteSpace(publicKeyPath)) throw new ArgumentException("Public key path must not be empty", nameof(publicKeyPath));
            if (!File.Exists(publicKeyPath)) throw new FileNotFoundException("Public key file not found", publicKeyPath);
            if (!File.Exists(inputPath)) throw new FileNotFoundException("Input file not found", inputPath);

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath)) ?? ".");

            var pubKey = ReadEncryptionKey(publicKeyPath) ?? throw new PgpException("No encryption-capable public key found in key file.");

            using var input = File.OpenRead(inputPath);
            using var outStream = File.Create(outputPath);
            using var finalOut = armor ? (Stream)new ArmoredOutputStream(outStream) : outStream;

            var random = new SecureRandom();

            var encGen = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Aes256,
                withIntegrity,
                random);

            encGen.AddMethod(pubKey);

            using var encryptedOut = encGen.Open(finalOut, new byte[BufferSize]);

            Stream compressionTarget = encryptedOut;
            PgpCompressedDataGenerator? compGen = null;
            Stream? compStream = null;
            if (compression != CompressionAlgorithmTag.Uncompressed)
            {
                compGen = new PgpCompressedDataGenerator(compression);
                compStream = compGen.Open(encryptedOut);
                compressionTarget = compStream;
            }

            var fileInfo = new FileInfo(inputPath);
            var fileName = fileInfo.Name;
            var fileModTime = fileInfo.LastWriteTimeUtc;

            var litGen = new PgpLiteralDataGenerator();
            using var literalOut = litGen.Open(
                compressionTarget,
                PgpLiteralData.Binary,
                fileName,
                fileInfo.Length,
                fileModTime);

            CopyStream(input, literalOut);

            literalOut.Close();
            compStream?.Dispose();
            encryptedOut.Close();
            if (armor && finalOut is ArmoredOutputStream aos)
            {
                aos.Close();
            }
        }

        public static void DecryptFileWithPrivateKey(string inputPath, string outputPath, string privateKeyPath, string? passphrase)
        {
            if (string.IsNullOrWhiteSpace(privateKeyPath)) throw new ArgumentException("Private key path must not be empty", nameof(privateKeyPath));
            if (!File.Exists(privateKeyPath)) throw new FileNotFoundException("Private key file not found", privateKeyPath);
            if (!File.Exists(inputPath)) throw new FileNotFoundException("Input file not found", inputPath);

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath)) ?? ".");

            using var input = File.OpenRead(inputPath);
            using var decoderStream = PgpUtilities.GetDecoderStream(input);
            var pgpFactory = new PgpObjectFactory(decoderStream);

            PgpObject? obj = pgpFactory.NextPgpObject();
            if (obj == null)
                throw new PgpException("Invalid PGP data: no objects found.");

            PgpEncryptedDataList? encList = obj as PgpEncryptedDataList;
            if (encList == null)
            {
                obj = pgpFactory.NextPgpObject();
                encList = obj as PgpEncryptedDataList;
            }
            if (encList == null)
                throw new PgpException("Invalid PGP data: expected encrypted data list.");

            using var keyIn = File.OpenRead(privateKeyPath);
            using var keyDecoder = PgpUtilities.GetDecoderStream(keyIn);
            var secretKeyBundle = new PgpSecretKeyRingBundle(keyDecoder);

            PgpPrivateKey? sKey = null;
            PgpPublicKeyEncryptedData? pke = null;
            foreach (PgpEncryptedData ed in encList.GetEncryptedDataObjects())
            {
                if (ed is PgpPublicKeyEncryptedData pked)
                {
                    var secretKey = secretKeyBundle.GetSecretKey(pked.KeyId);
                    if (secretKey != null)
                    {
                        try
                        {
                            sKey = ExtractPrivateKey(secretKey, passphrase);
                            pke = pked;
                            break;
                        }
                        catch (PgpException)
                        {
                            // Try next one if passphrase wrong for this key or extraction fails
                            sKey = null;
                            pke = null;
                        }
                    }
                }
            }

            if (sKey == null || pke == null)
                throw new PgpException("Unable to find a suitable private key for decryption (wrong key file or passphrase).");

            using var clearStream = pke.GetDataStream(sKey);
            var plainFactory = new PgpObjectFactory(clearStream);

            PgpObject? message = plainFactory.NextPgpObject();
            if (message == null)
                throw new PgpException("Invalid PGP data: empty message.");

            if (message is PgpCompressedData compressedData)
            {
                using var compDataStream = compressedData.GetDataStream();
                var compFactory = new PgpObjectFactory(compDataStream);
                message = compFactory.NextPgpObject();
            }

            if (message is not PgpLiteralData literal)
                throw new PgpException("Unsupported PGP packet: expected literal data.");

            using var literalStream = literal.GetInputStream();
            using var output = File.Create(outputPath);
            CopyStream(literalStream, output);

            if (pke.IsIntegrityProtected())
            {
                if (!pke.Verify())
                {
                    throw new PgpException("PGP integrity check failed (bad MDC or wrong passphrase).");
                }
            }
        }

        private static PgpPublicKey? ReadEncryptionKey(string publicKeyPath)
        {
            using var keyIn = File.OpenRead(publicKeyPath);
            using var decoder = PgpUtilities.GetDecoderStream(keyIn);
            var pubRings = new PgpPublicKeyRingBundle(decoder);

            foreach (PgpPublicKeyRing kRing in pubRings.GetKeyRings())
            {
                foreach (PgpPublicKey key in kRing.GetPublicKeys())
                {
                    if (key.IsEncryptionKey)
                    {
                        return key;
                    }
                }
            }
            return null;
        }

        private static PgpPrivateKey ExtractPrivateKey(PgpSecretKey secretKey, string? passphrase)
        {
            char[] pwd = passphrase?.ToCharArray() ?? Array.Empty<char>();
            return secretKey.ExtractPrivateKey(pwd);
        }

        private static void CopyStream(Stream input, Stream output)
        {
            var buffer = new byte[BufferSize];
            int read;
            while ((read = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, read);
            }
        }
    }
}
