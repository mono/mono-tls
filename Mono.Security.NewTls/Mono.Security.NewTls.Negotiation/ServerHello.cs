using System;
using System.Security.Cryptography;
using Mono.Security.Cryptography;

namespace Mono.Security.NewTls.Negotiation
{
	using Handshake;
	using Extensions;
	using Cipher;
	using X509;

	class ServerHello : NegotiationHandler
	{
		public ServerHello (TlsContext context)
			: base (context, NegotiationState.ServerHello)
		{
		}

		TlsServerHello hello;
		TlsCertificate certificate;
		TlsServerKeyExchange serverKeyExchange;
		TlsCertificateRequest certificateRequest;
		TlsServerHelloDone done;
		bool askedForCertificate;

		public override bool CanSendAlert {
			get { return true; }
		}

		bool UsingServerKeyExchange {
			get { return PendingCrypto.Cipher.ExchangeAlgorithmType == ExchangeAlgorithmType.Dhe || PendingCrypto.Cipher.ExchangeAlgorithmType == ExchangeAlgorithmType.EcDhe; }
		}

		protected override bool VerifyMessage (HandshakeType type)
		{
			switch (type) {
			case HandshakeType.ServerHello:
				return hello == null;

			case HandshakeType.Certificate:
				return hello != null && certificate == null && certificateRequest == null && done == null;

			case HandshakeType.ServerKeyExchange:
				if (!UsingServerKeyExchange)
					return false;
				return hello != null && certificate != null && certificateRequest == null && done == null;

			case HandshakeType.CertificateRequest:
				if (UsingServerKeyExchange && serverKeyExchange == null)
					return false;
				return hello != null && certificate != null && certificateRequest == null && done == null;

			case HandshakeType.ServerHelloDone:
				if (UsingServerKeyExchange && serverKeyExchange == null)
					return false;
				return hello != null && done == null;
			default:
				return false;
			}
		}

		protected override MessageStatus HandleMessage (Message message)
		{
			switch (message.Type) {
			case HandshakeType.ServerHello:
				hello = (TlsServerHello)message;
				HandleExtensions (hello);
				CheckSecureRenegotiation ();
				HandleServerHello (hello);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.Certificate:
				certificate = (TlsCertificate)message;
				HandleCertificate (certificate);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.ServerKeyExchange:
				serverKeyExchange = (TlsServerKeyExchange)message;
				HandleServerKeyExchange (serverKeyExchange);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.CertificateRequest:
				if (!Config.HasCredentials) {
					if (!askedForCertificate) {
						askedForCertificate = true;
						return MessageStatus.CredentialsNeeded;
					}
				}

				certificateRequest = (TlsCertificateRequest)message;
				HandleCertificateRequest (certificateRequest);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.ServerHelloDone:
				done = (TlsServerHelloDone)message;
				HandleServerHelloDone (done);
				return MessageStatus.GenerateOutput;

			default:
				throw new InvalidOperationException ();
			}
		}

		protected virtual void HandleServerHello (TlsServerHello message)
		{
			Context.VerifyServerProtocol (message.ServerProtocol);

			// Server random
			HandshakeParameters.ServerRandom = message.ServerRandom;

			// Session ID
			HandshakeParameters.SessionId = message.SessionID;

			HandshakeParameters.SupportedCiphers = CipherSuiteFactory.GetSupportedCiphers (Context.NegotiatedProtocol);

			// Cipher suite
			if (!HandshakeParameters.SupportedCiphers.Contains (message.SelectedCipher)) {
				// The server has sent an invalid ciphersuite
				throw new TlsException (AlertDescription.InsuficientSecurity, "Invalid cipher suite received from server");
			}

			var cipher = CipherSuiteFactory.CreateCipherSuite (Context.NegotiatedProtocol, message.SelectedCipher);
			#if DEBUG_FULL
			if (Context.EnableDebugging)
				cipher.EnableDebugging = true;
			#endif
			Session.PendingCrypto = cipher.Initialize (false, Context.NegotiatedProtocol);
		}

		protected virtual void HandleExtensions (TlsServerHello message)
		{
			foreach (var extension in message.Extensions) {
				if (!HandshakeParameters.RequestedExtensions.HasExtension (extension))
					throw new TlsException (AlertDescription.UnsupportedExtension);
				if (HandshakeParameters.ActiveExtensions.HasExtension (extension))
					throw new TlsException (AlertDescription.UnsupportedExtension);

				HandleExtension (extension);
			}
		}

		protected virtual void HandleExtension (TlsExtension extension)
		{
			#if DEBUG_FULL
			if (Context.EnableDebugging)
				DebugHelper.WriteLine ("Handle Server Extension: {0}", extension);
			#endif
			if (!extension.ProcessClient (Context))
				throw new TlsException (AlertDescription.UnsupportedExtension);
			HandshakeParameters.ActiveExtensions.Add (extension);
		}

		protected virtual void HandleCertificate (TlsCertificate message)
		{
			if (message.Certificates == null || message.Certificates.Count < 1)
				throw new TlsException (AlertDescription.CertificateUnknown);

			var exchangeAlgorithm = PendingCrypto.Cipher.ExchangeAlgorithmType;
			if (!CertificateManager.VerifyServerCertificate (Context, message.Certificates [0], exchangeAlgorithm))
				throw new TlsException (AlertDescription.UnsupportedCertificate);

			CertificateManager.CheckRemoteCertificate (Config, message.Certificates);
			PendingCrypto.ServerCertificates = message.Certificates;
			PendingCrypto.RemoteCertificateVerified = true;
		}

		protected virtual void HandleCertificateRequest (TlsCertificateRequest message)
		{
			Session.ClientCertificateParameters = message.Parameters;
		}

		protected virtual void HandleServerKeyExchange (TlsServerKeyExchange message)
		{
			if (!PendingCrypto.RemoteCertificateVerified)
				throw new TlsException (AlertDescription.UnexpectedMessage);
			if (PendingCrypto.Cipher.ExchangeAlgorithmType != ExchangeAlgorithmType.Dhe)
				throw new TlsException (AlertDescription.UnexpectedMessage);

			HandshakeParameters.KeyExchange = message.KeyExchange;
			HandshakeParameters.KeyExchange.HandleServer (Context);
		}

		void CheckSecureRenegotiation ()
		{
			// We requested it and the server agreed.
			if (HandshakeParameters.RequestedSecureNegotiation && HandshakeParameters.SecureNegotiationSupported) {
				Session.SecureRenegotiation = true;
				return;
			}

			// It was already enabled, refuse to disable.
			if (Session.SecureRenegotiation)
				throw new TlsException (AlertDescription.HandshakeFailure);

			// Did we actually request it?
			if (!HandshakeParameters.RequestedSecureNegotiation) {
				Config.ForceDisableRenegotiation ();
				return;
			}

			// We requested, but the server refused.
			if ((Config.RenegotiationFlags & RenegotiationFlags.AbortHandshakeIfUnsupported) != 0)
				throw new TlsException (AlertDescription.HandshakeFailure);

			Config.ForceDisableRenegotiation ();
		}

		protected virtual void HandleServerHelloDone (TlsServerHelloDone message)
		{
		}

		protected virtual X509CertificateCollection GetCertificates ()
		{
			var certificates = new X509CertificateCollection ();

			var certificate = Config.Certificate;
			if (certificate == null)
				return certificates;

			var verifyVertificate = true;
			#if INSTRUMENTATION
			if (Context.HasInstrument (HandshakeInstrumentType.OverrideClientCertificateSelection))
				verifyVertificate = false;
			#endif

			var exchangeAlgorithm = PendingCrypto.Cipher.ExchangeAlgorithmType;
			if (verifyVertificate && !CertificateManager.VerifyClientCertificate (Context, certificate, exchangeAlgorithm))
				throw new TlsException (AlertDescription.UnsupportedCertificate);

			certificates.Add (certificate);
			return certificates;
		}

		public TlsCertificate ClientCertificate {
			get;
			private set;
		}

		public TlsCertificateVerify CertificateVerify {
			get;
			private set;
		}

		public TlsClientKeyExchange ClientKeyExchange {
			get;
			private set;
		}

		protected virtual TlsCertificate GenerateClientCertificate ()
		{
			if (certificateRequest == null)
				return null;

			PendingCrypto.ClientCertificates = GetCertificates ();
			return new TlsCertificate (PendingCrypto.ClientCertificates);
		}

		protected virtual TlsCertificateVerify GenerateCertificateVerify ()
		{
			if (ClientCertificate == null || PendingCrypto.ClientCertificates.Count == 0)
				return null;

			switch (Context.NegotiatedProtocol) {
			case TlsProtocolCode.Tls10:
				PendingCrypto.CertificateSignature = new SignatureTls10 ();
				break;
			case TlsProtocolCode.Tls11:
				PendingCrypto.CertificateSignature = new SignatureTls11 ();
				break;
			case TlsProtocolCode.Tls12:
				PendingCrypto.CertificateSignature = new SignatureTls12 (SelectSignatureType ());
				break;
			default:
				throw new NotSupportedException ();
			}

			HandshakeParameters.HandshakeMessages.CreateSignature (PendingCrypto.CertificateSignature, Config.PrivateKey);

			#if DEBUG_FULL
			if (Context.EnableDebugging)
				DebugHelper.WriteLine ("Generate CertificateVerify: {0} {1}", PendingCrypto.CertificateSignature, Config.Certificate.SubjectName);
			#endif

			return new TlsCertificateVerify (PendingCrypto.CertificateSignature);
		}

		protected virtual TlsClientKeyExchange GenerateClientKeyExchange ()
		{
			if (PendingCrypto.Cipher.ExchangeAlgorithmType == ExchangeAlgorithmType.Rsa)
				HandshakeParameters.KeyExchange = new RSAKeyExchange ();

			HandshakeParameters.KeyExchange.GenerateClient (Context);

			return new TlsClientKeyExchange (HandshakeParameters.KeyExchange);
		}

		protected virtual SignatureAndHashAlgorithm SelectSignatureType ()
		{
			return Context.SignatureProvider.SelectClientSignatureAlgorithm (Context);
		}

		protected virtual TlsFinished GenerateFinished ()
		{
			var digest = HandshakeParameters.HandshakeMessages.GetHash (Session.Write.Cipher.HandshakeHashType);
			var hash = Session.Write.Cipher.PRF.ComputeClientHash (Session.Write.MasterSecret, digest);
			Session.ClientVerifyData = hash;
			return new TlsFinished (hash);
		}

		protected override NegotiationHandler GenerateOutput (TlsMultiBuffer outgoing)
		{
			ClientCertificate = GenerateClientCertificate ();
			if (ClientCertificate != null)
				outgoing.Add (Context.EncodeHandshakeRecord (ClientCertificate));

			// Send Client Key Exchange
			ClientKeyExchange = GenerateClientKeyExchange ();
			outgoing.Add (Context.EncodeHandshakeRecord (ClientKeyExchange));

			CertificateVerify = GenerateCertificateVerify ();
			if (CertificateVerify != null)
				outgoing.Add (Context.EncodeHandshakeRecord (CertificateVerify));

			// Now initialize session cipher with the generated keys
			Session.PendingCrypto.InitializeCipher ();

			SendChangeCipherSpec (outgoing);

			outgoing.Add (Context.EncodeHandshakeRecord (GenerateFinished ()));

			return Context.CreateNegotiationHandler (NegotiationState.ServerFinished);
		}
	}
}

