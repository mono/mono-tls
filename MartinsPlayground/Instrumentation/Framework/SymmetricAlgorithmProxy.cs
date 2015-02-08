using System;
using System.Security.Cryptography;

namespace Mono.Security.Instrumentation.Framework
{
	public class SymmetricAlgorithmProxy : SymmetricAlgorithm
	{
		SymmetricAlgorithm algorithm;

		public SymmetricAlgorithmProxy (SymmetricAlgorithm algorithm)
		{
			this.algorithm = algorithm;
		}

		public override int BlockSize {
			get { return algorithm.BlockSize; }
			set { algorithm.BlockSize = value; }
		}

		public override int FeedbackSize {
			get { return algorithm.FeedbackSize; }
			set { algorithm.FeedbackSize = value; }
		}

		public override byte[] IV {
			get { return algorithm.IV; }
			set { algorithm.IV = value; }
		}

		public override byte[] Key {
			get { return algorithm.Key; }
			set { algorithm.Key = value; }
		}

		public override int KeySize {
			get { return algorithm.KeySize; }
			set { algorithm.KeySize = value; }
		}

		public override KeySizes[] LegalBlockSizes {
			get { return algorithm.LegalBlockSizes; }
		}

		public override KeySizes[] LegalKeySizes {
			get { return algorithm.LegalKeySizes; }
		}

		public override CipherMode Mode {
			get { return algorithm.Mode; }
			set { algorithm.Mode = value; }
		}

		public override PaddingMode Padding {
			get { return algorithm.Padding; }
			set { algorithm.Padding = value; }
		}

		public override ICryptoTransform CreateDecryptor ()
		{
			return algorithm.CreateDecryptor ();
		}

		public override ICryptoTransform CreateEncryptor ()
		{
			return algorithm.CreateEncryptor ();
		}

		public override ICryptoTransform CreateDecryptor (byte[] rgbKey, byte[] rgbIV)
		{
			return algorithm.CreateDecryptor (rgbKey, rgbIV);
		}

		public override ICryptoTransform CreateEncryptor (byte[] rgbKey, byte[] rgbIV)
		{
			return algorithm.CreateEncryptor (rgbKey, rgbIV);
		}

		public override void GenerateIV ()
		{
			algorithm.GenerateIV ();
		}

		public override void GenerateKey ()
		{
			algorithm.GenerateKey ();
		}

		protected override void Dispose (bool disposing)
		{
			algorithm.Dispose ();
		}
	}

}

