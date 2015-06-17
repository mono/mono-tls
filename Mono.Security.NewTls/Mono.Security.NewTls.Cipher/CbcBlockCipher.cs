//
// CbcBlockCipher.cs
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
using System;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	public class CbcBlockCipher : BlockCipherWithHMac
	{
		public CbcBlockCipher (bool isServer, TlsProtocolCode protocol, CipherSuite cipher)
			: base (isServer, protocol, cipher)
		{
		}

		SymmetricAlgorithm encryptionAlgorithm;
		SymmetricAlgorithm decryptionAlgorithm;
		ICryptoTransform encryptionCipher;
		ICryptoTransform decryptionCipher;

		public SymmetricAlgorithm EncryptionAlgorithm {
			get { return encryptionAlgorithm; }
			private set { encryptionAlgorithm = Add (value); }
		}

		public SymmetricAlgorithm DecryptionAlgorithm {
			get { return decryptionAlgorithm; }
			private set { decryptionAlgorithm = Add (value); }
		}

		SymmetricAlgorithm CreateEncryptionAlgorithm ()
		{
			switch (Cipher.CipherAlgorithmType) {
#if !BOOTSTRAP_BASIC
			case CipherAlgorithmType.Aes128:
			case CipherAlgorithmType.Aes256:
				return Aes.Create ();
#endif
			default:
				throw new NotSupportedException ();
			}
		}

		protected virtual SymmetricAlgorithm CreateEncryptionAlgorithm (bool forEncryption)
		{
			// Create and configure algorithm
			var algorithm = CreateEncryptionAlgorithm ();
			algorithm.Mode = CipherMode.CBC;
			algorithm.Padding = PaddingMode.None;
			algorithm.KeySize = Cipher.ExpandedKeyMaterialSize * 8;
			algorithm.BlockSize = BlockSize * 8;

			if (IsClient)
				algorithm.Key = (forEncryption ? ClientWriteKey : ServerWriteKey).Buffer;
			else
				algorithm.Key = (forEncryption ? ServerWriteKey : ClientWriteKey).Buffer;

			return algorithm;
		}

		public override void InitializeCipher ()
		{
			#if DEBUG_FULL
			if (Cipher.EnableDebugging)
				DebugHelper.WriteLine ("INITIALIZE CIPHER: {0}", BlockSize);
			#endif

			EncryptionAlgorithm = CreateEncryptionAlgorithm (true);
			DecryptionAlgorithm = CreateEncryptionAlgorithm (false);

			// Legacy mode for TLS 1.0
			if (Cipher.HasFixedIV) {
				EncryptionAlgorithm.IV = (IsClient ? ClientWriteIV : ServerWriteIV).Buffer;
				DecryptionAlgorithm.IV = (IsClient ? ServerWriteIV : ClientWriteIV).Buffer;

				encryptionCipher = Add (EncryptionAlgorithm.CreateEncryptor ());
				decryptionCipher = Add (DecryptionAlgorithm.CreateDecryptor ());
			}

			base.InitializeCipher ();
		}

		protected override int HeaderSize {
			get { return Cipher.HasFixedIV ? 0 : BlockSize; }
		}

		protected override void EncryptRecord (DisposeContext d, IBufferOffsetSize input)
		{
			ICryptoTransform cipher;
			if (!Cipher.HasFixedIV) {
				EncryptionAlgorithm.GenerateIV ();
				cipher = d.Add (EncryptionAlgorithm.CreateEncryptor ());
			} else {
				cipher = encryptionCipher;
			}

			if (!Cipher.HasFixedIV)
				Buffer.BlockCopy (EncryptionAlgorithm.IV, 0, input.Buffer, input.Offset, BlockSize);

			var ret = cipher.TransformBlock (input.Buffer, input.Offset + HeaderSize, input.Size - HeaderSize, input.Buffer, input.Offset + HeaderSize);
			if (ret <= 0 || ret != input.Size - HeaderSize)
				throw new InvalidOperationException ();

			if (Cipher.HasFixedIV) {
				var IV = new byte [BlockSize];
				Buffer.BlockCopy (input.Buffer, input.Offset + input.Size - BlockSize, IV, 0, BlockSize);
				EncryptionAlgorithm.IV = IV;
			}
		}

		protected override int DecryptRecord (DisposeContext d, IBufferOffsetSize input, IBufferOffsetSize output)
		{
			if ((input.Size % BlockSize) != 0)
				return -1;

			int ivSize;
			ICryptoTransform cipher;
			if (!Cipher.HasFixedIV) {
				var IV = new byte [BlockSize];
				Buffer.BlockCopy (input.Buffer, input.Offset, IV, 0, BlockSize);
				ivSize = BlockSize;

				DecryptionAlgorithm.IV = IV;
				cipher = d.Add (DecryptionAlgorithm.CreateDecryptor ());
			} else {
				ivSize = 0;
				cipher = decryptionCipher;
			}

			var ret = cipher.TransformBlock (input.Buffer, input.Offset + ivSize, input.Size - ivSize, output.Buffer, output.Offset);
			if (ret <= 0 || ret != input.Size - ivSize)
				return -1;

			if (Cipher.HasFixedIV) {
				var IV = new byte [BlockSize];
				Buffer.BlockCopy (input.Buffer, input.Offset + input.Size - BlockSize, IV, 0, BlockSize);
				DecryptionAlgorithm.IV = IV;
			}

			return ret;
		}
	}
}

