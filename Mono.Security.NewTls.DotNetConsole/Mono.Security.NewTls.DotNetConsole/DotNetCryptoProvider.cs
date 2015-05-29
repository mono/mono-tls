//
// DotNetCryptoProvider.cs
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
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
using Xamarin.AsyncTests;

namespace Mono.Security.NewTls.DotNetConsole
{
	using TestFramework;
	using Cipher;

	class DotNetCryptoProvider : ICryptoProvider, IHashTestHost
	{
		#region ICryptoProvider implementation

		public IRandomNumberGenerator GetRandomNumberGenerator ()
		{
			return this;
		}

		public bool IsSupported (CryptoProviderType type, bool needsEncryption)
		{
			if (needsEncryption)
				return false;
			return type == CryptoProviderType.DotNet;
		}

		public IHashTestHost GetHashTestHost (CryptoProviderType type)
		{
			return this;
		}

		public IEncryptionTestHost GetEncryptionTestHost (CryptoProviderType type, CryptoTestParameters parameters)
		{
			throw new NotImplementedException ();
		}

		#endregion

		#region IHashTestHost implementation

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

		public byte[] TestHMac (HandshakeHashType algorithm, byte[] key, byte[] data)
		{
			var hmac = HMac.Create (algorithm, new SecureBuffer (key));

			hmac.Reset ();
			hmac.TransformBlock (data, 0, data.Length);

			var output = new byte [hmac.MacSize];
			hmac.TransformFinalBlock (output, 0, output.Length);

			DebugHelper.WriteLine ("RESULT");
			DebugHelper.WriteBuffer (output);

			return output;
		}

		#endregion

		#region IRandomNumberGenerator implementation

		public byte[] GetRandomBytes (int count)
		{
			throw new NotImplementedException ();
		}

		#endregion

		#region ITestInstance implementation

		Task ITestInstance.Initialize (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.FromResult<object> (null);
		}

		Task ITestInstance.PreRun (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.FromResult<object> (null);
		}

		Task ITestInstance.PostRun (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.FromResult<object> (null);
		}

		Task ITestInstance.Destroy (TestContext ctx, CancellationToken cancellationToken)
		{
			return Task.FromResult<object> (null);
		}

		#endregion
	}
}

