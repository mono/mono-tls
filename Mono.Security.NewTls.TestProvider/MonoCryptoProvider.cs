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
	public class MonoCryptoProvider : ICryptoTestProvider
	{
		RandomNumberGenerator rng = RandomNumberGenerator.Create ();

		public Task Initialize (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.FromResult<object> (null);
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
			return Task.FromResult<object> (null);
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

		public ICryptoTestContext CreateContext ()
		{
			return new MonoCryptoContext (TlsProtocolCode.Tls12, true);
		}
	}
}

