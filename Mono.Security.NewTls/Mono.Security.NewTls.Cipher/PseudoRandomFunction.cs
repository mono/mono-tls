//
// PseudoRandomFunction.cs
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
using System.Text;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	#if INSIDE_MONO_NEWTLS
	using Handshake;
	#endif

	public abstract class PseudoRandomFunction
	{
		#if INSIDE_MONO_NEWTLS
		public SecureBuffer ComputeClientHash (SecureBuffer secret, SecureBuffer digest)
		{
			return PRF (secret, TlsFinished.ClientSeed, digest, 12);
		}

		public SecureBuffer ComputeServerHash (SecureBuffer secret, SecureBuffer digest)
		{
			return PRF (secret, TlsFinished.ServerSeed, digest, 12);
		}
		#endif

		public SecureBuffer ComputeMasterSecret (SecureBuffer preMasterSecret, SecureBuffer cs)
		{
			return PRF (preMasterSecret, "master secret", cs, 48);
		}

		public TlsBuffer ComputeKeyExpansion (DisposeContext d, SecureBuffer masterSecret, SecureBuffer sc, int size)
		{
			var buffer = d.Add (PRF (d, masterSecret, "key expansion", sc, size));
			return new TlsBuffer (buffer.Buffer);
		}

		public SecureBuffer ComputeFinalClientWriteKey (SecureBuffer writeKey, SecureBuffer cs, int size)
		{
			return PRF (writeKey, "client write key", cs, size);
		}

		public SecureBuffer ComputeFinalServerWriteKey (SecureBuffer writeKey, SecureBuffer cs, int size)
		{
			return PRF (writeKey, "server write key", cs, size);
		}

		public SecureBuffer ComputeInitialIV (SecureBuffer cs, int size)
		{
			if (this is PseudoRandomFunctionTls12)
				throw new InvalidOperationException ();
			return PRF (new SecureBuffer (CipherSuite.EmptyArray), "IV block", cs, size);
		}

		public SecureBuffer PRF (SecureBuffer secret, string label, SecureBuffer data, int length)
		{
			using (var d = new DisposeContext ())
				return PRF (d, secret, label, data, length);
		}

		protected abstract SecureBuffer PRF (DisposeContext d, SecureBuffer secret, string label, SecureBuffer data, int length);

		static int Min (int a, int b)
		{
			return a < b ? a : b;
		}

		protected SecureBuffer Expand (DisposeContext d, HMac hmac, string label, SecureBuffer seed, int length)
		{
			var blockSize = hmac.MacSize;
			var iterations = (int)(length / blockSize);
			if ((length % blockSize) > 0)
				iterations++;

			var resMacs = d.CreateBuffer (length);
			var resOff = 0;

			var tempBuf = d.CreateBuffer (blockSize);

			var labelBytes = Encoding.ASCII.GetBytes (label);

			for (int i = 1; i <= iterations; i++) {
				hmac.Reset ();
				if (i == 1) {
					hmac.TransformBlock (labelBytes, 0, labelBytes.Length);
					hmac.TransformBlock (seed.Buffer, 0, seed.Size);
				} else {
					hmac.TransformBlock (tempBuf.Buffer, 0, blockSize);
				}
				hmac.TransformFinalBlock (tempBuf.Buffer, 0, blockSize);

				hmac.Reset ();
				hmac.TransformBlock (tempBuf.Buffer, 0, blockSize);
				hmac.TransformBlock (labelBytes, 0, labelBytes.Length);
				hmac.TransformBlock (seed.Buffer, 0, seed.Size);
				hmac.TransformFinalBlock (resMacs.Buffer, resOff, Min (length - resOff, blockSize));
				resOff += blockSize;
			}

			return new SecureBuffer (resMacs.StealBuffer ());
		}
	}
}

