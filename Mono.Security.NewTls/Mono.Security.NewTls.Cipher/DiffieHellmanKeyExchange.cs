using System;
using Mono.Security.Cryptography;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Cipher
{
	class DiffieHellmanKeyExchange : KeyExchange
	{
		byte[] P;
		byte[] G;
		byte[] Y;

		DiffieHellmanManaged dh;
		TlsProtocolCode protocol;

		public override ExchangeAlgorithmType ExchangeAlgorithm {
			get { return ExchangeAlgorithmType.Dhe; }
		}

		public Signature Signature {
			get;
			private set;
		}

		public override void ReadServer (TlsBuffer incoming)
		{
			P = incoming.ReadBytes (incoming.ReadInt16 ());
			G = incoming.ReadBytes (incoming.ReadInt16 ());
			Y = incoming.ReadBytes (incoming.ReadInt16 ());

			Signature = Signature.Read (protocol, incoming);
		}

		public override void ReadClient (TlsBuffer incoming)
		{
			Y = incoming.ReadBytes (incoming.ReadInt16 ());
		}

		public override void WriteClient (TlsStream stream)
		{
			stream.Write ((short)Y.Length);
			stream.Write (Y);
		}

		public override void GenerateClient (TlsContext ctx)
		{
			using (var dh = new DiffieHellmanManaged (P, G, 0)) {
				using (var X = new SecureBuffer (dh.DecryptKeyExchange (Y))) {
					Y = dh.CreateKeyExchange ();
					ComputeMasterSecret (ctx, X);
				}
			}
		}

		public DiffieHellmanKeyExchange (TlsProtocolCode protocol)
		{
			this.protocol = protocol;
		}

		public DiffieHellmanKeyExchange (TlsContext ctx)
		{
			this.protocol = ctx.NegotiatedProtocol;

			switch (protocol) {
			case TlsProtocolCode.Tls12:
				Signature = new SignatureTls12 (ctx.Session.ServerSignatureAlgorithm);
				break;
			case TlsProtocolCode.Tls10:
				Signature = new SignatureTls10 ();
				break;
			case TlsProtocolCode.Tls11:
				Signature = new SignatureTls11 ();
				break;
			default:
				throw new NotSupportedException ();
			}

			dh = new DiffieHellmanManaged ();
			Y = dh.CreateKeyExchange ();
			var dhparams = dh.ExportParameters (true);
			P = dhparams.P;
			G = dhparams.G;

			using (var buffer = CreateParameterBuffer (ctx.HandshakeParameters))
				Signature.Create (buffer, ctx.Configuration.PrivateKey);
		}

		void AssertSignatureAlgorithm (TlsContext ctx)
		{
			ctx.SignatureProvider.AssertProtocol (ctx, protocol);
			if (protocol == TlsProtocolCode.Tls12) {
				var signature12 = (SignatureTls12)Signature;
				ctx.SignatureProvider.AssertServerSignatureAlgorithm (ctx, signature12.SignatureAlgorithm);
			}
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

		public override void HandleClient (TlsContext ctx, KeyExchange clientExchange)
		{
			var serverDh = (DiffieHellmanKeyExchange)clientExchange;
			using (var X = new SecureBuffer (dh.DecryptKeyExchange (serverDh.Y))) {
				ComputeMasterSecret (ctx, X);
			}
		}

		SecureBuffer CreateParameterBuffer (HandshakeParameters hsp)
		{
			var length = P.Length + G.Length + Y.Length + 6;

			var buffer = new TlsBuffer (64 + length);
			buffer.Write (hsp.ClientRandom.Buffer);
			buffer.Write (hsp.ServerRandom.Buffer);
			buffer.Write ((short)P.Length);
			buffer.Write (P);
			buffer.Write ((short)G.Length);
			buffer.Write (G);
			buffer.Write ((short)Y.Length);
			buffer.Write (Y);
			return new SecureBuffer (buffer.Buffer);
		}

		public override void WriteServer (TlsStream stream)
		{
			stream.Write ((short)P.Length);
			stream.Write (P);
			stream.Write ((short)G.Length);
			stream.Write (G);
			stream.Write ((short)Y.Length);
			stream.Write (Y);

			Signature.Write (stream);
		}

		protected override void Clear ()
		{
			if (P != null) {
				Array.Clear (P, 0, P.Length);
				P = null;
			}
			if (G != null) {
				Array.Clear (G, 0, G.Length);
				G = null;
			}
			if (Y != null) {
				Array.Clear (Y, 0, Y.Length);
				Y = null;
			}
			if (dh != null) {
				#if !BOOTSTRAP_BASIC
				dh.Dispose ();
				#endif
				dh = null;
			}
		}

		public void Dump ()
		{
			DebugHelper.WriteLine ("DiffieHellmanKeyExchange");
			DebugHelper.WriteLine ("  P", P);
			DebugHelper.WriteLine ("  G", G);
			DebugHelper.WriteLine ("  Y", Y);
		}
	}
}

