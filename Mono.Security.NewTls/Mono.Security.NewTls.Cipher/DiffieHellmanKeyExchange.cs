using System;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Cipher
{
	class DiffieHellmanKeyExchange : KeyExchange
	{
		byte[] P;
		byte[] G;
		byte[] Y;

		DiffieHellmanManaged dh;

		public override ExchangeAlgorithmType ExchangeAlgorithm {
			get { return ExchangeAlgorithmType.DiffieHellman; }
		}

		public SignatureAndHashAlgorithm SignatureAlgorithm {
			get;
			private set;
		}

		public SecureBuffer Signature {
			get;
			private set;
		}

		public override void ReadServer (TlsBuffer incoming)
		{
			P = incoming.ReadBytes (incoming.ReadInt16 ());
			G = incoming.ReadBytes (incoming.ReadInt16 ());
			Y = incoming.ReadBytes (incoming.ReadInt16 ());

			SignatureAlgorithm = new SignatureAndHashAlgorithm (incoming);
			Signature = incoming.ReadSecureBuffer (incoming.ReadInt16 ());
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

		void CreateServer (TlsContext ctx)
		{
			dh = new DiffieHellmanManaged ();
			Y = dh.CreateKeyExchange ();
			var dhparams = dh.ExportParameters (true);
			P = dhparams.P;
			G = dhparams.G;

			using (var buffer = CreateParameterBuffer (ctx.HandshakeParameters))
				Signature = SignatureHelper.CreateSignature (SignatureAlgorithm, buffer, ctx.Configuration.PrivateKey);
		}

		public static DiffieHellmanKeyExchange Create (TlsContext ctx, SignatureAndHashAlgorithm algorithm)
		{
			var exchange = new DiffieHellmanKeyExchange ();
			exchange.SignatureAlgorithm = algorithm;
			exchange.CreateServer (ctx);
			return exchange;
		}

		public override void HandleServer (TlsContext ctx)
		{
			using (var buffer = CreateParameterBuffer (ctx.HandshakeParameters)) {
				var certificate = ctx.Session.PendingCrypto.ServerCertificates [0];
				if (!SignatureHelper.VerifySignature (SignatureAlgorithm, buffer, certificate.RSA, Signature))
					throw new TlsException (AlertDescription.HandshakeFailure);
			}
		}

		public override void HandleClient (TlsContext ctx, KeyExchange serverExchange)
		{
			var serverDh = (DiffieHellmanKeyExchange)serverExchange;
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

			SignatureAlgorithm.Encode (stream);
			stream.Write ((short)Signature.Size);
			stream.Write (Signature.Buffer);
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

