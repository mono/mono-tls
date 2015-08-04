using System;

namespace Mono.Security.NewTls.Negotiation
{
	using Handshake;
	using Extensions;
	using Cipher;
	using X509;

	class ServerConnection : NegotiationHandler
	{
		public bool Renegotiating {
			get;
			private set;
		}

		public ServerConnection (TlsContext context, bool renegotiating)
			: base (context, renegotiating ? NegotiationState.RenegotiatingServerConnection : NegotiationState.InitialServerConnection)
		{
			Renegotiating = renegotiating;
		}

		TlsClientHello hello;
		bool askedForCertificate;

		public override bool CanSendAlert {
			get { return true; }
		}

		protected override bool VerifyMessage (HandshakeType type)
		{
			switch (type) {
			case HandshakeType.ClientHello:
				return hello == null;
			default:
				return false;
			}
		}

		protected override HandshakeMessage CreateMessage (HandshakeType type, TlsBuffer incoming)
		{
			if (type != HandshakeType.ClientHello)
				throw new TlsException (AlertDescription.UnexpectedMessage);

			if (Renegotiating) {
				var flags = Config.RenegotiationFlags;
				if ((flags & RenegotiationFlags.DisallowRenegotiation) != 0)
					throw new TlsException (AlertDescription.HandshakeFailure, "Renegotiation not allowed.");
				if (!Session.SecureRenegotiation)
					throw new TlsException (AlertDescription.HandshakeFailure, "Renegotiation not allowed.");
			}

			StartHandshake ();

			return base.CreateMessage (type, incoming);
		}

		protected override MessageStatus HandleMessage (Message message)
		{
			if (message.Type != HandshakeType.ClientHello)
				throw new TlsException (AlertDescription.UnexpectedMessage);

			if (Renegotiating) {
				var flags = Config.RenegotiationFlags;
				if ((flags & RenegotiationFlags.DisallowRenegotiation) != 0)
					throw new TlsException (AlertDescription.HandshakeFailure, "Renegotiation not allowed.");
				if (!Session.SecureRenegotiation)
					throw new TlsException (AlertDescription.HandshakeFailure, "Renegotiation not allowed.");
			}

			if (!Config.HasCredentials) {
				if (!Renegotiating && !askedForCertificate) {
					askedForCertificate = true;
					return MessageStatus.CredentialsNeeded;
				}

				throw new TlsException (AlertDescription.InternalError, "No server certificate or private key.");
			}

			hello = (TlsClientHello)message;
			HandleClientHello (hello);
			return Renegotiating ? MessageStatus.Renegotiate : MessageStatus.GenerateOutput;
		}

		public TlsCertificate ServerCertificate {
			get;
			private set;
		}

		public TlsServerKeyExchange ServerKeyExchange {
			get;
			private set;
		}

		public TlsCertificateRequest CertificateRequest {
			get;
			private set;
		}

		protected virtual void HandleClientHello (TlsClientHello message)
		{
			Context.VerifyClientProtocol (message.ClientProtocol);

			HandshakeParameters.ClientRandom = message.ClientRandom;

			SelectCipher (message);

			ProcessExtensions (message);
		}

		protected virtual void SelectCipher (TlsClientHello message)
		{
			CipherSuiteCollection supportedCiphers;
			if (Settings.RequestedCiphers != null)
				supportedCiphers = new CipherSuiteCollection (Context.NegotiatedProtocol, Settings.RequestedCiphers);
			else
				supportedCiphers = CipherSuiteFactory.GetDefaultCiphers (Context.NegotiatedProtocol);

			HandshakeParameters.SupportedCiphers = supportedCiphers;

			CipherSuite selectedCipher = null;
			foreach (var code in message.ClientCiphers) {
				var idx = HandshakeParameters.SupportedCiphers.IndexOf (code);
				if (idx < 0)
					continue;
				var cipher = HandshakeParameters.SupportedCiphers [idx];
				selectedCipher = CipherSuiteFactory.CreateCipherSuite (Context.NegotiatedProtocol, cipher);
				break;
			}

			if (selectedCipher == null)
				throw new TlsException (AlertDescription.HandshakeFailure, "Invalid cipher suite received from client");

			#if DEBUG_FULL
			if (Context.EnableDebugging)
				selectedCipher.EnableDebugging = true;
			#endif

			#if DEBUG_FULL
			if (Context.EnableDebugging)
				DebugHelper.WriteLine ("Selected Cipher: {0}", selectedCipher);
			#endif

			// FIXME: Select best one.
			Session.PendingCrypto = selectedCipher.Initialize (true, Context.NegotiatedProtocol);
		}

		protected virtual void ProcessExtensions (TlsClientHello message)
		{
			foreach (var extension in message.Extensions)
				ProcessExtension (extension);
		}

		protected virtual void ProcessExtension (TlsExtension extension)
		{
			extension = extension.ProcessServer (Context);
			if (extension != null)
				HandshakeParameters.ActiveExtensions.Add (extension);
		}

		protected virtual X509CertificateCollection GetCertificates ()
		{
			var certificates = new X509CertificateCollection ();
			if (Config.Certificate != null)
				certificates.Add (Config.Certificate);
			return certificates;
		}

		protected virtual TlsServerHello GenerateServerHello ()
		{
			var serverUnixTime = HandshakeParameters.GetUnixTime ();
			HandshakeParameters.ServerRandom = Context.Session.GetSecureRandomBytes (32);
			TlsBuffer.WriteInt32 (HandshakeParameters.ServerRandom.Buffer, 0, serverUnixTime);

			return new TlsServerHello (
				Context.NegotiatedProtocol, HandshakeParameters.ServerRandom,
				HandshakeParameters.SessionId, PendingCrypto.Cipher.Code, HandshakeParameters.ActiveExtensions);
		}

		protected virtual TlsCertificate GenerateServerCertificate ()
		{
			PendingCrypto.ServerCertificates = GetCertificates ();
			return new TlsCertificate (PendingCrypto.ServerCertificates);
		}

		protected virtual TlsServerKeyExchange GenerateServerKeyExchange ()
		{
			if (PendingCrypto.Cipher.ExchangeAlgorithmType == ExchangeAlgorithmType.RsaSign) {
				HandshakeParameters.KeyExchange = new RSAKeyExchange ();
				return null;
			} else if (PendingCrypto.Cipher.ExchangeAlgorithmType != ExchangeAlgorithmType.DiffieHellman) {
				throw new InvalidOperationException ();
			}

			var dh = new DiffieHellmanKeyExchange (Context);
			HandshakeParameters.KeyExchange = dh;

			return new TlsServerKeyExchange (dh);
		}

		protected virtual TlsCertificateRequest GenerateCertificateRequest ()
		{
			Session.AskedForCertificate = Settings.AskForClientCertificate;
			#if INSTRUMENTATION
			if (Renegotiating && Context.HasInstrument (HandshakeInstrumentType.AskForClientCertificate))
				Session.AskedForCertificate = true;
			#endif

			if (!Session.AskedForCertificate)
				return null;

			Session.ClientCertificateParameters = Context.SignatureProvider.GetServerCertificateParameters (Context);
			return new TlsCertificateRequest (Context.NegotiatedProtocol, Session.ClientCertificateParameters);
		}

		protected virtual void Resolve ()
		{
			if (Context.NegotiatedProtocol == TlsProtocolCode.Tls12) {
				Session.SignatureParameters = Context.SignatureProvider.GetServerSignatureParameters (Context);
				Session.ServerSignatureAlgorithm = Context.SignatureProvider.SelectServerSignatureAlgorithm (Context);
			}
		}

		protected override NegotiationHandler GenerateOutput (TlsMultiBuffer outgoing)
		{
			Resolve ();

			outgoing.Add (Context.EncodeHandshakeRecord (GenerateServerHello ()));

			ServerCertificate = GenerateServerCertificate ();
			if (ServerCertificate != null)
				outgoing.Add (Context.EncodeHandshakeRecord (ServerCertificate));

			ServerKeyExchange = GenerateServerKeyExchange ();
			if (ServerKeyExchange != null)
				outgoing.Add (Context.EncodeHandshakeRecord (ServerKeyExchange));

			CertificateRequest = GenerateCertificateRequest ();
			if (CertificateRequest != null)
				outgoing.Add (Context.EncodeHandshakeRecord (CertificateRequest));

			outgoing.Add (Context.EncodeHandshakeRecord (new TlsServerHelloDone ()));

			return Context.CreateNegotiationHandler (NegotiationState.ClientKeyExchange);
		}
	}
}

