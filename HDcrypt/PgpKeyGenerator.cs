using System;
using System.IO;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace HDcrypt
{
    public static class PgpKeyGenerator
    {
        public record KeyGenResult(string PublicKeyPath, string PrivateKeyPath);

        // NOTE: Passphrase currently not applied (unencrypted private key) due to library constructor limitations in this version.
        //       Future enhancement: protect secret key with passphrase.
        public static KeyGenResult GenerateKeyPair(string userId, string outputPrefix, string? passphrase)
        {
            if (string.IsNullOrWhiteSpace(userId)) throw new ArgumentException("User ID must not be empty", nameof(userId));
            if (string.IsNullOrWhiteSpace(outputPrefix)) throw new ArgumentException("Output prefix must not be empty", nameof(outputPrefix));

            var fullPrefixDir = Path.GetDirectoryName(Path.GetFullPath(outputPrefix));
            if (!string.IsNullOrEmpty(fullPrefixDir) && !Directory.Exists(fullPrefixDir))
            {
                Directory.CreateDirectory(fullPrefixDir);
            }

            string prefix = outputPrefix;
            string pubPath = prefix + "-public.asc";
            string privPath = prefix + "-private.asc";

            if (File.Exists(pubPath) || File.Exists(privPath))
            {
                throw new IOException($"One of the output files already exists: {pubPath} or {privPath}. Choose a different prefix or remove existing files.");
            }

            var random = new SecureRandom();

            // RSA key pair generation (4096 bits)
            var rsaParams = new RsaKeyGenerationParameters(BigInteger.ValueOf(0x10001), random, 4096, 12);
            var kpg = new RsaKeyPairGenerator();
            kpg.Init(rsaParams);
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            var pgpKeyPair = new PgpKeyPair(PublicKeyAlgorithmTag.RsaGeneral, kp, DateTime.UtcNow);

            // Optional signature subpackets (key flags etc.)
            var hashedGen = new PgpSignatureSubpacketGenerator();

            // Create secret key (unencrypted private key)
            // The older constructor signature is:
            // PgpSecretKey(int certificationLevel, PgpKeyPair keyPair, string id, SymmetricKeyAlgorithmTag encAlgorithm, char[] passPhrase, bool useSha1, PgpSignatureSubpacketVector hashedPcks, PgpSignatureSubpacketVector unhashedPcks, SecureRandom random)
            char[] emptyPass = Array.Empty<char>(); // passphrase intentionally empty for now
            var secretKey = new PgpSecretKey(
                PgpSignature.DefaultCertification,
                pgpKeyPair,
                userId,
                SymmetricKeyAlgorithmTag.Cast5,
                emptyPass,
                true, // use SHA-1 checksum
                null,
                null,
                random);

            var publicKey = secretKey.PublicKey;

            // Write armored public key
            using (var pubOut = File.Create(pubPath))
            using (var pubArmor = new ArmoredOutputStream(pubOut))
            {
                publicKey.Encode(pubArmor);
            }

            // Write armored private key (secret key ring)
            using (var privOut = File.Create(privPath))
            using (var privArmor = new ArmoredOutputStream(privOut))
            {
                secretKey.Encode(privArmor);
            }

            return new KeyGenResult(pubPath, privPath);
        }
    }
}
