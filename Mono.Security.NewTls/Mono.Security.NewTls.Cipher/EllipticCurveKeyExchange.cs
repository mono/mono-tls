//
// EllipticCurveKeyExchange.cs
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
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Mono.Security.NewTls.Cipher
{
	using EC;

	class EllipticCurveKeyExchange : KeyExchange
	{
		public EllipticCurveKeyExchange ()
		{
		}

		public EllipticCurveKeyExchange (TlsContext context)
		{
			curveType = ECCurveType.named_curve;
			namedCurve = NamedCurve.secp256k1;
			domainParameters = NamedCurveHelper.GetECParameters (namedCurve);

			GenerateKeyPair (context, domainParameters, out serverQ, out serverD);
			publicBytes = ExternalizeKey (serverQ);

			Signature = new SignatureTls12 (context.Session.ServerSignatureAlgorithm);
			using (var buffer = CreateParameterBuffer (context.HandshakeParameters))
				Signature.Create (buffer, context.Configuration.PrivateKey);
		}

		public override ExchangeAlgorithmType ExchangeAlgorithm {
			get { return ExchangeAlgorithmType.EcDhe; }
		}

		public Signature Signature {
			get;
			private set;
		}

		public override void ReadClient (TlsBuffer incoming)
		{
			clientKey = incoming.ReadBytes (incoming.ReadByte ());
		}

		public override void GenerateClient (TlsContext context)
		{
			GenerateKeyPair (context, domainParameters, out clientQ, out clientD);
			clientKey = ExternalizeKey (clientQ);

			var agreement = CalculateAgreement (serverQ, clientD);
			using (var preMaster = new SecureBuffer (agreement.ToByteArrayUnsigned ()))
				ComputeMasterSecret (context, preMaster);
		}

		public override void HandleClient (TlsContext context, KeyExchange clientExchange)
		{
			var clientKey = ((EllipticCurveKeyExchange)clientExchange).clientKey;

			clientQ = domainParameters.Curve.DecodePoint (clientKey);

			var agreement = CalculateAgreement (clientQ, serverD);
			using (var preMaster = new SecureBuffer (agreement.ToByteArrayUnsigned ()))
				ComputeMasterSecret (context, preMaster);
		}

		public override void WriteClient (TlsStream stream)
		{
			stream.Write ((byte)clientKey.Length);
			stream.Write (clientKey);
		}

		ECCurveType curveType;
		NamedCurve namedCurve;
		ECDomainParameters domainParameters;
		ECPoint clientQ;
		ECPoint serverQ;
		BigInteger clientD;
		BigInteger serverD;
		byte[] publicBytes;
		byte[] clientKey;

		public override void ReadServer (TlsBuffer incoming)
		{
			curveType = (ECCurveType)incoming.ReadByte ();

			//  Currently, we only support named curves
			if (curveType == ECCurveType.named_curve) {
				namedCurve = (NamedCurve)incoming.ReadInt16 ();

				// TODO Check namedCurve is one we offered?
				domainParameters = NamedCurveHelper.GetECParameters (namedCurve);
			} else {
				// TODO Add support for explicit curve parameters
				throw new TlsException (AlertDescription.HandshakeFailure, "Unsupported elliptic curve type `{0}'.", curveType);
			}

			var publicLength = incoming.ReadByte ();
			publicBytes = incoming.ReadBytes (publicLength);

			// TODO Check RFC 4492 for validation
			serverQ = domainParameters.Curve.DecodePoint (publicBytes);

			Signature = Signature.Read (TlsProtocolCode.Tls12, incoming);
		}

		void AssertSignatureAlgorithm (TlsContext ctx)
		{
			ctx.SignatureProvider.AssertProtocol (ctx, TlsProtocolCode.Tls12);
			var signature12 = (SignatureTls12)Signature;
			ctx.SignatureProvider.AssertServerSignatureAlgorithm (ctx, signature12.SignatureAlgorithm);
		}

		public override void HandleServer (TlsContext ctx)
		{
			AssertSignatureAlgorithm (ctx);
			using (var buffer = CreateParameterBuffer (ctx.HandshakeParameters)) {
				var certificate = ctx.Session.PendingCrypto.ServerCertificates [0];
				if (!Signature.Verify (buffer, certificate.RSA))
					throw new TlsException (AlertDescription.HandshakeFailure);
			}
		}

		SecureBuffer CreateParameterBuffer (HandshakeParameters hsp)
		{
			var length = 4 + publicBytes.Length;

			var buffer = new TlsBuffer (64 + length);
			buffer.Write (hsp.ClientRandom.Buffer);
			buffer.Write (hsp.ServerRandom.Buffer);
			buffer.Write ((byte)curveType);
			buffer.Write ((short)namedCurve);
			buffer.Write ((byte)publicBytes.Length);
			buffer.Write (publicBytes);
			return new SecureBuffer (buffer.Buffer);
		}

		public override void WriteServer (TlsStream stream)
		{
			stream.Write ((byte)curveType);
			stream.Write ((short)namedCurve);

			stream.Write ((byte)publicBytes.Length);
			stream.Write (publicBytes);

			Signature.Write (stream);
		}

		protected override void Clear ()
		{
			;
		}

		static byte[] ExternalizeKey (ECPoint q)
		{
			// TODO Add support for compressed encoding and SPF extension

			/*
			 * RFC 4492 5.7. ...an elliptic curve point in uncompressed or compressed format.
			 * Here, the format MUST conform to what the server has requested through a
			 * Supported Point Formats Extension if this extension was used, and MUST be
			 * uncompressed if this extension was not used.
			 */
			return q.GetEncoded ();
		}

		/*
		 * Given the domain parameters this routine Generates an EC key
		 * pair in accordance with X9.62 section 5.2.1 pages 26, 27.
		 */
		internal static void GenerateKeyPair (TlsContext context, ECDomainParameters parameters, out ECPoint q, out BigInteger d)
		{
			BigInteger n = parameters.N;

			do {
				d = new BigInteger (n.BitLength, context.Session.SecureRandom);
			} while (d.SignValue == 0 || (d.CompareTo (n) >= 0));

			q = parameters.G.Multiply (d);
		}

		internal static BigInteger CalculateAgreement (ECPoint q, BigInteger d)
		{
			ECPoint p = q.Multiply (d);

			// if ( p.IsInfinity ) throw new Exception("d*Q == infinity");

			return p.X.ToBigInteger();
		}
	}
}

