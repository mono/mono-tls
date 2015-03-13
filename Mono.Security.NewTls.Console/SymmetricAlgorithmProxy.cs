//
// SymmetricAlgorithmProxy.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Console
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

