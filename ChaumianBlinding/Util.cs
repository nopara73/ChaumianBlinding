using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Text;

namespace ChaumianBlinding
{
    class Util
    {
        public static byte[] GetRandomBytes(int count)
        {
            byte[] bytes = new byte[count];
            new SecureRandom().NextBytes(bytes);
            return bytes;
        }

        public static AsymmetricCipherKeyPair GenerateKeyPair()
        {
            // Generate a 2048-bit RSA key pair.
            RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
            BigInteger RSA_F4 = BigInteger.ValueOf(65537);
            generator.Init(new RsaKeyGenerationParameters(
                        RSA_F4,
                        new SecureRandom(),
                        2048,
                        100)); // See A.15.2 IEEE P1363 v2 D1 for certainty parameter
            return generator.GenerateKeyPair();
        }
    }
}
