//
// HMac.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2014 Xamarin Inc. (http://www.xamarin.com)
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

//
// Copied and adjusted from BouncyCastle.
//
using System;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	class HMac : DisposeContext
	{
		const byte IPAD = (byte)0x36;
		const byte OPAD = (byte)0x5C;

		readonly HashAlgorithm algorithm;
		readonly int digestSize;
		readonly int blockSize;

		readonly SecureBuffer inputPad;
		readonly SecureBuffer outputPad;

		bool final;

		public int MacSize {
			get { return digestSize; }
		}

		public static int GetMacSize (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5:
				return 16;
			case HashAlgorithmType.Sha1:
				return 20;
			case HashAlgorithmType.Sha256:
				return 32;
			case HashAlgorithmType.Sha384:
				return 48;
			default:
				throw new NotSupportedException ();
			}
		}

		public static HashAlgorithm CreateHash (HashAlgorithmType type)
		{
			switch (type) {
			case HashAlgorithmType.Md5:
				return MD5.Create ();
			case HashAlgorithmType.Sha1:
				return SHA1.Create ();
			case HashAlgorithmType.Sha256:
				return SHA256.Create ();
			case HashAlgorithmType.Sha384:
				return SHA384.Create ();
			default:
				throw new NotSupportedException ();
			}
		}

		public static HMac Create (HashAlgorithmType type, SecureBuffer key)
		{
			switch (type) {
			case HashAlgorithmType.Md5:
				return new HMac (MD5.Create (), 64, key);
			case HashAlgorithmType.Sha1:
				return new HMac (SHA1.Create (), 64, key);
			case HashAlgorithmType.Sha256:
				return new HMac (SHA256.Create (), 64, key);
			case HashAlgorithmType.Sha384:
				return new HMac (SHA384.Create (), 128, key);
			default:
				throw new NotSupportedException ();
			}
		}

		public static HMac Create (HandshakeHashType type, SecureBuffer key)
		{
			switch (type) {
			case HandshakeHashType.SHA256:
				return new HMac (SHA256.Create (), 64, key);
			case HandshakeHashType.SHA384:
				return new HMac (SHA384.Create (), 128, key);
			default:
				throw new NotSupportedException ();
			}
		}

		HMac (HashAlgorithm algorithm, int blockSize, SecureBuffer key)
		{
			this.algorithm = Add (algorithm);
			this.digestSize = algorithm.HashSize / 8;
			this.blockSize = blockSize;

			this.inputPad = CreateBuffer (blockSize);
			this.outputPad = CreateBuffer (blockSize);

			Init (key);
		}

		void Init (SecureBuffer key)
		{
			algorithm.Initialize ();

			int keyLength = key.Size;

			if (key.Size > blockSize) {
				algorithm.TransformFinalBlock (key.Buffer, 0, keyLength);
				Buffer.BlockCopy (algorithm.Hash, 0, inputPad.Buffer, 0, digestSize);

				keyLength = digestSize;
			} else {
				Array.Copy (key.Buffer, 0, inputPad.Buffer, 0, keyLength);
			}

			Array.Clear (inputPad.Buffer, keyLength, blockSize - keyLength);
			Array.Copy (inputPad.Buffer, 0, outputPad.Buffer, 0, blockSize);

			xor (inputPad.Buffer, IPAD);
			xor (outputPad.Buffer, OPAD);

			// Initialise the digest
			algorithm.TransformBlock (inputPad.Buffer, 0, inputPad.Size, null, 0);

			final = false;
		}

		public void TransformBlock (byte[] input, int inOff, int len)
		{
			if (final)
				throw new InvalidOperationException ();

			algorithm.TransformBlock (input, inOff, len, null, 0);
		}

		public void TransformFinalBlock (byte[] output, int outOff, int len)
		{
			if (final)
				throw new InvalidOperationException ();
			if (len > digestSize)
				throw new ArgumentException ();

			algorithm.TransformFinalBlock (TlsBuffer.EmptyArray, 0, 0);
			var tmp = algorithm.Hash;

			algorithm.Initialize ();

			algorithm.TransformBlock (outputPad.Buffer, 0, outputPad.Size, null, 0);
			algorithm.TransformFinalBlock (tmp, 0, tmp.Length);

			Buffer.BlockCopy (algorithm.Hash, 0, output, outOff, len);

			// Initialise the digest
			algorithm.TransformBlock (inputPad.Buffer, 0, inputPad.Size, null, 0);

			final = true;
		}

		public byte[] TransformFinalBlock ()
		{
			var output = new byte [MacSize];
			TransformFinalBlock (output, 0, output.Length);
			return output;
		}

		public void Reset ()
		{
			// Reset underlying digest
			algorithm.Initialize ();

			// Initialise the digest
			algorithm.TransformBlock (inputPad.Buffer, 0, inputPad.Size, null, 0);

			final = false;
		}

		static void xor (byte[] a, byte n)
		{
			for (int i = 0; i < a.Length; ++i) {
				a [i] ^= n;
			}
		}
	}
}


