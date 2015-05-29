//
// GaloisCounterCipher.cs
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
	using Org.BouncyCastle.Crypto.Engines;
	using Org.BouncyCastle.Crypto.Modes;
	using Org.BouncyCastle.Crypto.Parameters;
	using Org.BouncyCastle.Crypto;

	class GaloisCounterCipher : BlockCipher
	{
		public GaloisCounterCipher (bool isServer, TlsProtocolCode protocol, CipherSuite cipher)
			: base (isServer, protocol, cipher)
		{
			ImplicitNonceSize = 4;
			ExplicitNonceSize = 8;
			MacSize = 16;
		}

		public override void InitializeCipher ()
		{
			if (ImplicitNonceSize != Cipher.FixedIvSize)
				throw new TlsException (AlertDescription.IlegalParameter);
			if (MacSize != Cipher.BlockSize)
				throw new TlsException (AlertDescription.IlegalParameter);
#if !BOOTSTRAP_BASIC
			random = Add (RandomNumberGenerator.Create ()); 
#endif
		}

		RandomNumberGenerator random;

		public int ImplicitNonceSize {
			get;
			private set;
		}

		public int ExplicitNonceSize {
			get;
			private set;
		}

		public int MacSize {
			get;
			private set;
		}

		public override int MinExtraEncryptedBytes {
			get { return ExplicitNonceSize + MacSize; }
		}

		public override int MaxExtraEncryptedBytes {
			get { return ExplicitNonceSize + MacSize; }
		}

		public override int GetEncryptedSize (int size)
		{
			return size + ExplicitNonceSize + MacSize;
		}

		protected override int Decrypt (DisposeContext d, ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output)
		{
			var implicitNonce = IsClient ? ServerWriteIV : ClientWriteIV;
			var writeKey = IsClient ? ServerWriteKey : ClientWriteKey;

			#if DEBUG_FULL
			if (Cipher.EnableDebugging) {
				DebugHelper.WriteLine ("FIXED IV", implicitNonce);
				DebugHelper.WriteLine ("WRITE KEY", writeKey);
				DebugHelper.WriteLine ("SEQUENCE: {0}", ReadSequenceNumber);
			}
			#endif

			var length = input.Size - ExplicitNonceSize;

			var aad = new TlsBuffer (13);
			aad.Write (ReadSequenceNumber);
			aad.Write ((byte)contentType);
			aad.Write ((short)Protocol);
			aad.Write ((short)(length - MacSize));

			#if DEBUG_FULL
			if (Cipher.EnableDebugging)
				DebugHelper.WriteFull ("TAG", aad);
			#endif

			var gcm = new GcmBlockCipher (new AesEngine ());
			var key = new KeyParameter (writeKey.Buffer);

			var nonce = d.CreateBuffer (ImplicitNonceSize + ExplicitNonceSize);
			Buffer.BlockCopy (implicitNonce.Buffer, 0, nonce.Buffer, 0, ImplicitNonceSize);
			Buffer.BlockCopy (input.Buffer, input.Offset, nonce.Buffer, ImplicitNonceSize, ExplicitNonceSize);

			#if DEBUG_FULL
			if (Cipher.EnableDebugging)
				DebugHelper.WriteLine ("NONCE", nonce);
			#endif

			var parameters = new AeadParameters (key, 128, nonce.Buffer, aad.Buffer);
			gcm.Init (false, parameters);

			int ret;
			try {
				ret = gcm.ProcessBytes (input.Buffer, input.Offset + ExplicitNonceSize, length, output.Buffer, output.Offset);

				ret += gcm.DoFinal (output.Buffer, output.Offset + ret);
			} catch (CryptoException ex) {
				throw new TlsException (AlertDescription.BadRecordMAC, ex.Message);
			}

			return ret;
		}

		protected virtual void CreateExplicitNonce (SecureBuffer explicitNonce)
		{
			random.GetBytes (explicitNonce.Buffer);
		}

		protected override int Encrypt (DisposeContext d, ContentType contentType, IBufferOffsetSize input, IBufferOffsetSize output)
		{
			var implicitNonce = IsClient ? ClientWriteIV : ServerWriteIV;
			var writeKey = IsClient ? ClientWriteKey : ServerWriteKey;

			#if DEBUG_FULL
			if (Cipher.EnableDebugging) {
				DebugHelper.WriteLine ("FIXED IV", implicitNonce);
				DebugHelper.WriteLine ("WRITE KEY", writeKey);
				DebugHelper.WriteLine ("SEQUENCE: {0}", WriteSequenceNumber);
			}
			#endif

			var length = input.Size;

			var aad = new TlsBuffer (13);
			aad.Write (WriteSequenceNumber);
			aad.Write ((byte)contentType);
			aad.Write ((short)Protocol);
			aad.Write ((short)length);

			#if DEBUG_FULL
			if (Cipher.EnableDebugging)
				DebugHelper.WriteFull ("TAG", aad);
			#endif

			var gcm = new GcmBlockCipher (new AesEngine ());
			var key = new KeyParameter (writeKey.Buffer);
			var nonce = d.CreateBuffer (ImplicitNonceSize + ExplicitNonceSize);
			var explicitNonce = d.CreateBuffer (ExplicitNonceSize);
			CreateExplicitNonce (explicitNonce);
			Buffer.BlockCopy (implicitNonce.Buffer, 0, nonce.Buffer, 0, ImplicitNonceSize);
			Buffer.BlockCopy (explicitNonce.Buffer, 0, nonce.Buffer, ImplicitNonceSize, ExplicitNonceSize);

			Buffer.BlockCopy (explicitNonce.Buffer, 0, output.Buffer, output.Offset, ExplicitNonceSize);

			#if DEBUG_FULL
			if (Cipher.EnableDebugging)
				DebugHelper.WriteLine ("NONCE", nonce);
			#endif

			var parameters = new AeadParameters (key, 128, nonce.Buffer, aad.Buffer);
			gcm.Init (true, parameters);

			int ret;

			try {
				ret = gcm.ProcessBytes (input.Buffer, input.Offset, length, output.Buffer, output.Offset + ExplicitNonceSize);

				ret += gcm.DoFinal (output.Buffer, output.Offset + ExplicitNonceSize + ret);
			} catch (CryptoException ex) {
				throw new TlsException (AlertDescription.BadRecordMAC, ex.Message);
			}

			return ExplicitNonceSize + ret;
		}
	}
}

