using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using System;
using System.Collections.Generic;
using System.Text;
using ChaumianBlinding.Crypto;
using System.Linq;

namespace ChaumianBlinding
{
    static class Blinding
    {
        public static void CanVerifyBlind()
        {
            // generate rsa keypair
            var key = new RsaKey();

            // generate blinding factor with pubkey
            // blind message
            byte[] message = Encoding.ASCII.GetBytes("sing me please");
            var blindingResult = key.PubKey.Blind(message);

            // sign the blinded message
            var signature = key.Sign(blindingResult.BlindedData);

            // unblind the signature
            var unblindedSignature = key.PubKey.Unblind(signature, blindingResult.BlindingFactor);

            // unblind message
            var unblindedMessage = key.PubKey.Unblind(blindingResult.BlindedData, blindingResult.BlindingFactor);

            // verify the original data is signed
            Console.WriteLine(key.PubKey.Verify(unblindedSignature, message));
        }
    }
}
