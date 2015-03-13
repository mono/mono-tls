//
// MonoCryptoProvider.cs
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
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections;
using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;
using Xamarin.AsyncTests;

namespace Mono.Security.NewTls.TestProvider
{
	public class MonoCryptoProvider : IHashTestHost, IEncryptionTestHost
	{
		RandomNumberGenerator rng = RandomNumberGenerator.Create ();

		public CryptoTestParameters Parameters {
			get;
			set;
		}

		CipherSuite cipher;
		CryptoParameters crypto;

		class MyCbcBlockCipher : CbcBlockCipher
		{
			CryptoTestParameters parameters;

			public MyCbcBlockCipher (CryptoTestParameters parameters, CipherSuite cipher)
				: base (parameters.IsServer, parameters.Protocol, cipher)
			{
				this.parameters = parameters;
			}

			protected override SymmetricAlgorithm CreateEncryptionAlgorithm (bool forEncryption)
			{
				return new MyAlgorithm (base.CreateEncryptionAlgorithm (forEncryption), parameters.IV);
			}

			protected override byte GetPaddingSize (int size)
			{
				var padLen = (byte)(BlockSize - size % BlockSize);
				if (padLen == BlockSize)
					padLen = 0;

				padLen += (byte)(parameters.ExtraPaddingBlocks * BlockSize);

				return padLen;
			}
		}

		class MyAlgorithm : SymmetricAlgorithmProxy
		{
			byte[] iv;

			public MyAlgorithm (SymmetricAlgorithm algorithm, byte[] iv)
				: base (algorithm)
			{
				this.iv = iv;
			}

			public override void GenerateIV ()
			{
				base.IV = iv;
			}
		}

		class MyGaloisCounterCipher : GaloisCounterCipher
		{
			CryptoTestParameters parameters;

			public MyGaloisCounterCipher (CryptoTestParameters parameters, CipherSuite cipher)
				: base (parameters.IsServer, parameters.Protocol, cipher)
			{
				this.parameters = parameters;
			}

			protected override void CreateExplicitNonce (SecureBuffer explicitNonce)
			{
				Buffer.BlockCopy (parameters.ExplicitNonce, 0, explicitNonce.Buffer, 0, parameters.ExplicitNonce.Length);
			}
		}

		public Task Initialize (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.Run (() => {
				if (Parameters == null)
					return;

				cipher = CipherSuiteFactory.CreateCipherSuite (Parameters.Protocol, Parameters.Code);

				if (Parameters.IsGCM) {
					crypto = new MyGaloisCounterCipher (Parameters, cipher);

					crypto.ServerWriteKey = SecureBuffer.CreateCopy (Parameters.Key);
					crypto.ClientWriteKey = SecureBuffer.CreateCopy (Parameters.Key);
					crypto.ServerWriteIV = SecureBuffer.CreateCopy (Parameters.ImplicitNonce);
					crypto.ClientWriteIV = SecureBuffer.CreateCopy (Parameters.ImplicitNonce);

					crypto.InitializeCipher ();
				} else {
					crypto = new MyCbcBlockCipher (Parameters, cipher);

					crypto.ServerWriteKey = SecureBuffer.CreateCopy (Parameters.Key);
					crypto.ClientWriteKey = SecureBuffer.CreateCopy (Parameters.Key);
					crypto.ServerWriteMac = SecureBuffer.CreateCopy (Parameters.MAC);
					crypto.ClientWriteMac = SecureBuffer.CreateCopy (Parameters.MAC);

					crypto.InitializeCipher ();
				}
			});
		}

		public Task PreRun (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.FromResult<object> (null);
		}

		public Task PostRun (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.FromResult<object> (null);
		}

		public Task Destroy (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.Run (() => {
				if (crypto != null) {
					crypto.Dispose ();
					crypto = null;
				}
			});
		}

		public byte[] GetRandomBytes (int count)
		{
			var buffer = new byte [count];
			rng.GetBytes (buffer);
			return buffer;
		}

		public byte[] TestPRF (HandshakeHashType algorithm, byte[] secret, string seed, byte[] data, int length)
		{
			var prf = new PseudoRandomFunctionTls12 (algorithm);

			var result = prf.PRF (new SecureBuffer (secret), seed, new SecureBuffer (data), length);
			return result.StealBuffer ();
		}

		HashAlgorithm CreateHash (HandshakeHashType algorithm)
		{
			switch (algorithm) {
			case HandshakeHashType.SHA256:
				return SHA256.Create ();
			case HandshakeHashType.SHA384:
				return SHA384.Create ();
			default:
				throw new NotSupportedException ();
			}
		}

		public byte[] TestDigest (HandshakeHashType algorithm, byte[] data)
		{
			var hash = CreateHash (algorithm);
			hash.TransformFinalBlock (data, 0, data.Length);
			return hash.Hash;
		}

		public bool SupportsEncryption {
			get { return true; }
		}

		public int BlockSize {
			get { return cipher.BlockSize; }
		}

		public int GetEncryptedSize (int size)
		{
			return crypto.GetEncryptedSize (size);
		}

		public int MinExtraEncryptedBytes {
			get { return crypto.MinExtraEncryptedBytes; }
		}

		public int MaxExtraEncryptedBytes {
			get { return crypto.MaxExtraEncryptedBytes; }
		}

		public void EncryptRecord (ContentType contentType, IBufferOffsetSize input, TlsStream output)
		{
			crypto.WriteSequenceNumber = 0;
			TlsContext.EncodeRecord (Parameters.Protocol, ContentType.ApplicationData, crypto, input, output);
		}

		public IBufferOffsetSize Encrypt (IBufferOffsetSize input)
		{
			crypto.WriteSequenceNumber = 0;
			return crypto.Encrypt (ContentType.ApplicationData, input);
		}

		public int Encrypt (IBufferOffsetSize input, IBufferOffsetSize output)
		{
			crypto.WriteSequenceNumber = 0;
			return crypto.Encrypt (ContentType.ApplicationData, input, output);
		}

		public IBufferOffsetSize Decrypt (IBufferOffsetSize input)
		{
			crypto.ReadSequenceNumber = 0;
			return crypto.Decrypt (ContentType.ApplicationData, input);
		}

		public int Decrypt (IBufferOffsetSize input, IBufferOffsetSize output)
		{
			crypto.ReadSequenceNumber = 0;
			return crypto.Decrypt (ContentType.ApplicationData, input, output);
		}
	}
}

