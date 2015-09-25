//
// RSAKeyExchange.cs
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
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	class RSAKeyExchange : KeyExchange
	{
		byte[] encryptedPreMasterSecret;

		public override ExchangeAlgorithmType ExchangeAlgorithm {
			get { return ExchangeAlgorithmType.Rsa; }
		}

		public override void GenerateClient (TlsContext ctx)
		{
			// Compute pre master secret
			using (var preMasterSecret = ctx.Session.GetSecureRandomBytes (48)) {
				preMasterSecret.Buffer [0] = (byte)((short)ctx.Configuration.RequestedProtocol >> 8);
				preMasterSecret.Buffer [1] = (byte)ctx.Configuration.RequestedProtocol;

				RSA rsa = null;
				// Create a new RSA key
				var serverCertificates = ctx.Session.PendingCrypto.ServerCertificates;
				if (serverCertificates == null || serverCertificates.Count == 0) {
					// FIXME: Should have received ServerKeyExchange message.
					throw new TlsException (AlertDescription.IlegalParameter);
				} else {
					rsa = new RSAManaged (serverCertificates [0].RSA.KeySize);
					rsa.ImportParameters (serverCertificates [0].RSA.ExportParameters (false));
				}

				ComputeMasterSecret (ctx, preMasterSecret);

				// Encrypt premaster_sercret
				var formatter = new RSAPKCS1KeyExchangeFormatter (rsa);
				encryptedPreMasterSecret = formatter.CreateKeyExchange (preMasterSecret.Buffer);
				rsa.Clear ();
			}
		}

		public override void ReadClient (TlsBuffer incoming)
		{
			encryptedPreMasterSecret = incoming.ReadBytes (incoming.ReadInt16 ());
		}

		public override void HandleClient (TlsContext ctx, KeyExchange serverExchange)
		{
			// Read client premaster secret
			var encryptedPreMaster = ((RSAKeyExchange)serverExchange).encryptedPreMasterSecret;

			if (!ctx.Configuration.HasCredentials)
				throw new TlsException (AlertDescription.BadCertificate, "Server certificate Private Key unavailable.");

			// Decrypt premaster secret
			var deformatter = new RSAPKCS1KeyExchangeDeformatter (ctx.Configuration.PrivateKey);

			using (var preMasterSecret = new SecureBuffer (deformatter.DecryptKeyExchange (encryptedPreMaster))) {
				// Create master secret
				ComputeMasterSecret (ctx, preMasterSecret);
			}
		}

		public override void WriteClient (TlsStream stream)
		{
			stream.Write ((short)encryptedPreMasterSecret.Length);
			stream.Write (encryptedPreMasterSecret);
		}

		public override void ReadServer (TlsBuffer incoming)
		{
			throw new InvalidOperationException ();
		}

		public override void HandleServer (TlsContext ctx)
		{
			throw new InvalidOperationException ();
		}

		public override void WriteServer (TlsStream stream)
		{
			throw new InvalidOperationException ();
		}

		protected override void Clear ()
		{
			if (encryptedPreMasterSecret != null) {
				Array.Clear (encryptedPreMasterSecret, 0, encryptedPreMasterSecret.Length);
				encryptedPreMasterSecret = null;
			}
		}
	}
}

