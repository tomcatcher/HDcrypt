using System;
using System.IO;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;

namespace HDcrypt
{
    public static class PgpPasswordEncryptor
    {
        private const int BufferSize = 1 << 16; // 64KB

        public static void EncryptFile(string inputPath, string outputPath, string password, bool armor, bool withIntegrity, CompressionAlgorithmTag compression)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Password must not be empty", nameof(password));
            if (!File.Exists(inputPath)) throw new FileNotFoundException("Input file not found", inputPath);

            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath)) ?? ".");

            using var input = File.OpenRead(inputPath);
            using var outStream = File.Create(outputPath);
            using var finalOut = armor ? (Stream)new ArmoredOutputStream(outStream) : outStream;

            var random = new SecureRandom();

            var encGen = new PgpEncryptedDataGenerator(
                SymmetricKeyAlgorithmTag.Aes256,
                withIntegrity,
                random);

            encGen.AddMethod(password.ToCharArray(), HashAlgorithmTag.Sha1);

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

            // Close in reverse order
            literalOut.Close();
            compStream?.Dispose();
            encryptedOut.Close();
            if (armor && finalOut is ArmoredOutputStream aos)
            {
                aos.Close();
            }
        }

        public static void DecryptFile(string inputPath, string outputPath, string password)
        {
            if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Password must not be empty", nameof(password));
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

            PgpPbeEncryptedData? pbe = null;
            foreach (PgpEncryptedData ed in encList.GetEncryptedDataObjects())
            {
                if (ed is PgpPbeEncryptedData pbeData)
                {
                    pbe = pbeData;
                    break;
                }
            }

            if (pbe == null)
                throw new PgpException("No password-based encrypted data found in input.");

            using var clearStream = pbe.GetDataStream(password.ToCharArray());
            var plainFactory = new PgpObjectFactory(clearStream);

            PgpObject? message = plainFactory.NextPgpObject();
            if (message == null)
                throw new PgpException("Invalid PGP data: empty message.");

            // Keep compressed stream open until after copy & integrity verification
            Stream? compDataStream = null;
            if (message is PgpCompressedData compressedData)
            {
                compDataStream = compressedData.GetDataStream();
                var compFactory = new PgpObjectFactory(compDataStream);
                message = compFactory.NextPgpObject();
            }

            if (message is not PgpLiteralData literal)
                throw new PgpException("Unsupported PGP packet: expected literal data.");

            using var literalStream = literal.GetInputStream();
            using var output = File.Create(outputPath);
            CopyStream(literalStream, output);

            // Verify integrity before disposing compressed stream
            if (pbe.IsIntegrityProtected())
            {
                if (!pbe.Verify())
                {
                    compDataStream?.Dispose();
                    throw new PgpException("PGP integrity check failed (bad MDC or wrong password).");
                }
            }

            compDataStream?.Dispose();
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
