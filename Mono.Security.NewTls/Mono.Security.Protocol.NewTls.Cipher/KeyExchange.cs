//
// KeyExchange.cs
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
	abstract class KeyExchange : SecretParameters
	{
		public abstract ExchangeAlgorithmType ExchangeAlgorithm {
			get;
		}

		public static KeyExchange Create (ExchangeAlgorithmType algorithm)
		{
			switch (algorithm) {
			case ExchangeAlgorithmType.RsaSign:
				return new RSAKeyExchange ();
			case ExchangeAlgorithmType.DiffieHellman:
				return new DiffieHellmanKeyExchange ();
			default:
				throw new InvalidOperationException ();
			}
		}

		public abstract void ReadClient (TlsBuffer incoming);

		public abstract void GenerateClient (TlsContext ctx);

		public abstract void HandleClient (TlsContext context, KeyExchange serverExchange);

		public abstract void WriteClient (TlsStream stream);

		public abstract void ReadServer (TlsBuffer incoming);

		public abstract void HandleServer (TlsContext ctx);

		public abstract void WriteServer (TlsStream stream);

		protected void ComputeMasterSecret (TlsContext ctx, SecureBuffer preMasterSecret)
		{
			using (var d = new DisposeContext ())
				ComputeMasterSecret (d, ctx, preMasterSecret);
		}

		void ComputeMasterSecret (DisposeContext d, TlsContext ctx, SecureBuffer preMasterSecret)
		{
			// Compute ClientRandom + ServerRandom
			int clen = ctx.HandshakeParameters.ClientRandom.Size;
			int slen = ctx.HandshakeParameters.ServerRandom.Size;
			int rlen = clen + slen;
			var cs = d.CreateBuffer (rlen);
			Buffer.BlockCopy (ctx.HandshakeParameters.ClientRandom.Buffer, 0, cs.Buffer, 0, clen);
			Buffer.BlockCopy (ctx.HandshakeParameters.ServerRandom.Buffer, 0, cs.Buffer, clen, slen);

			// Server Random + Client Random
			var sc = d.CreateBuffer (rlen);
			Buffer.BlockCopy (ctx.HandshakeParameters.ServerRandom.Buffer, 0, sc.Buffer, 0, slen);
			Buffer.BlockCopy (ctx.HandshakeParameters.ClientRandom.Buffer, 0, sc.Buffer, slen, clen);

			// Create master secret
			var crypto = ctx.Session.PendingCrypto;
			crypto.MasterSecret = crypto.Cipher.PRF.ComputeMasterSecret (preMasterSecret, cs);

			#if DEBUG_FULL
			if (ctx.EnableDebugging) {
				DebugHelper.WriteLine ("CS", cs);
				DebugHelper.WriteLine ("SC", sc);
				DebugHelper.WriteLine ("PRE-MASTER", preMasterSecret);
				DebugHelper.WriteLine ("MASTER SECRET", crypto.MasterSecret.Buffer);
			}
			#endif

			var keyBlock = crypto.Cipher.PRF.ComputeKeyExpansion (d, crypto.MasterSecret, sc, crypto.Cipher.KeyBlockSize);

			#if DEBUG_FULL
			if (ctx.EnableDebugging) {
				DebugHelper.WriteLine ("KEY BLOCK SIZE: {0}", crypto.Cipher.KeyBlockSize);
				DebugHelper.WriteLine ("KEY BLOCK", keyBlock.Buffer);
			}
			#endif

			crypto.ClientWriteMac = keyBlock.ReadSecureBuffer (crypto.Cipher.HashSize);
			crypto.ServerWriteMac = keyBlock.ReadSecureBuffer (crypto.Cipher.HashSize);
			crypto.ClientWriteKey = keyBlock.ReadSecureBuffer (crypto.Cipher.KeyMaterialSize);
			crypto.ServerWriteKey = keyBlock.ReadSecureBuffer (crypto.Cipher.KeyMaterialSize);

			if (crypto.Cipher.HasFixedIV) {
				crypto.ClientWriteIV = keyBlock.ReadSecureBuffer (crypto.Cipher.FixedIvSize);
				crypto.ServerWriteIV = keyBlock.ReadSecureBuffer (crypto.Cipher.FixedIvSize);

				#if DEBUG_FULL
				if (ctx.EnableDebugging) {
					DebugHelper.WriteLine ("CLIENT IV", crypto.ClientWriteIV.Buffer);
					DebugHelper.WriteLine ("SERVER IV", crypto.ServerWriteIV.Buffer);
				}
				#endif
			}
		}
	}
}

