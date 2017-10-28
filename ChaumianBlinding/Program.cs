using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using ChaumianBlinding.Crypto;
using System;

namespace ChaumianBlinding
{
    interface IBank
    {
        // The bank's RSA public key
        RsaKeyParameters GetPublic();

        // Sign a coin request
        byte[] Sign(ICoinRequest coinRequest);

        // Verify a coin
        bool Verify(ICoin coin);
    }

    interface ICoin
    {
        // The coin's globally unique ID
        byte[] GetID();

        // The issuing bank's signature on the coin
        byte[] GetSignature();
    }

    interface ICoinRequest
    {
        // The message (blind) to be signed by the bank
        byte[] GetMessage();
    }

    class Program
    {
        private static IBank bank = CreateBank();

        private static IBank CreateBank()
        {
            // Create a new bank using a freshly generated RSA key pair.
            return new Bank(Util.GenerateKeyPair());
        }

        static void Main(string[] args)
        {
            Blinding.CanVerifyBlind();
            // Create a "protocoin" using the bank's public key. The protocoin
            // contains an internal blinding factor that is used to blind the
            // message to be signed by the bank.
            Protocoin protocoin = new Protocoin(bank.GetPublic());

            // Generate a coin request.
            CoinRequest coinRequest = protocoin.GenerateCoinRequest();

            PrintCoinRequest(coinRequest);

            // Ask the bank to sign the coin request.

            // Note: In practice the bank will be on a remote server and this will
            // be an asynchronous operation. The bank will verify Alice's
            // credentials and debit her account for every coin it issues.
            // Needless to say, the connection to the bank would have to be over a
            // secure channel.

            byte[] signature = bank.Sign(coinRequest);

            PrintBankSignature(signature);

            // Create a new coin using the bank's signature.
            Coin coin = protocoin.CreateCoin(signature);

            PrintCoin(coin);

            // The signature on the coin is different from the one the bank
            // returned earlier (magic!). Will the bank accept the coin as valid?
            // Let's see ...
            bool valid = bank.Verify(coin);

            if (valid)
            {
                // It should always print "OK"
                Console.WriteLine("OK");
            }
            else
            {
                Console.WriteLine("Fail!");
            }

            Console.ReadKey();
        }

        private static void PrintCoinRequest(CoinRequest coinRequest)
        {
            Console.WriteLine("MESSAGE TO BE SIGNED BY THE BANK:");
            Console.WriteLine("");
            Console.WriteLine(Base64.ToBase64String(coinRequest.GetMessage()));
            Console.WriteLine("");
        }

        private static void PrintBankSignature(byte[] signature)
        {
            Console.WriteLine("THE BANK'S SIGNATURE:");
            Console.WriteLine("");
            Console.WriteLine(Base64.ToBase64String(signature));
            Console.WriteLine("");
        }

        private static void PrintCoin(Coin coin)
        {
            Console.WriteLine("COIN:");
            Console.WriteLine("");
            Console.WriteLine(Base64.ToBase64String(coin.GetID()));
            Console.WriteLine("");
            Console.WriteLine(Base64.ToBase64String(coin.GetSignature()));
            Console.WriteLine("");
        }
    }

    class Bank : IBank
    {

        private AsymmetricCipherKeyPair keys;

        public Bank(AsymmetricCipherKeyPair keys)
        {
            this.keys = keys;
        }

        public RsaKeyParameters GetPublic()
        {
            return (RsaKeyParameters)keys.Public;
        }

        public byte[] Sign(ICoinRequest coinRequest)
        {
            // Sign the coin request using our private key.
            byte[] message = coinRequest.GetMessage();

            RsaEngine engine = new RsaEngine();
            engine.Init(true, keys.Private);

            return engine.ProcessBlock(message, 0, message.Length);
        }

        public bool Verify(ICoin coin)
        {
            // Verify that the coin has a valid signature using our public key.
            byte[] id = coin.GetID();
            byte[] signature = coin.GetSignature();

            PssSigner signer = new PssSigner(new RsaEngine(), new Sha1Digest(), 20);
            signer.Init(false, keys.Public);

            signer.BlockUpdate(id, 0, id.Length);

            return signer.VerifySignature(signature);
        }
    }

    class Coin : ICoin
    {

        private byte[] id;
        private byte[] signature;

        public Coin(byte[] id, byte[] signature)
        {
            this.id = id;
            this.signature = signature;
        }

        public byte[] GetID()
        {
            return id;
        }

        public byte[] GetSignature()
        {
            return signature;
        }
    }

    class CoinRequest : ICoinRequest
    {

        private byte[] message;

        public CoinRequest(byte[] message)
        {
            this.message = message;
        }

        public byte[] GetMessage()
        {
            return message;
        }
    }

    class Protocoin
    {
        private byte[] coinID;
        private RsaBlindingParameters blindingParams;

        public Protocoin(RsaKeyParameters pub)
        {
            // Create a 128-bit globally unique ID for the coin.
            coinID = Util.GetRandomBytes(16);

            // Generate a blinding factor using the bank's public key.
            RsaBlindingFactorGenerator blindingFactorGenerator
                = new RsaBlindingFactorGenerator();
            blindingFactorGenerator.Init(pub);

            BigInteger blindingFactor
                = blindingFactorGenerator.GenerateBlindingFactor();

            blindingParams = new RsaBlindingParameters(pub, blindingFactor);
        }

        public CoinRequest GenerateCoinRequest()
        {
            // "Blind" the coin and generate a coin request to be signed by the
            // bank.
            PssSigner signer = new PssSigner(new RsaBlindingEngine(),
                    new Sha1Digest(), 20);
            signer.Init(true, blindingParams);

            signer.BlockUpdate(coinID, 0, coinID.Length);

            byte[] sig = signer.GenerateSignature();

            return new CoinRequest(sig);
        }

        public Coin CreateCoin(byte[] signature)
        {
            // "Unblind" the bank's signature (so to speak) and create a new coin
            // using the ID and the unblinded signature.
            RsaBlindingEngine blindingEngine = new RsaBlindingEngine();
            blindingEngine.Init(false, blindingParams);

            byte[] s = blindingEngine.ProcessBlock(signature, 0, signature.Length);

            return new Coin(coinID, s);
        }
    }    
}