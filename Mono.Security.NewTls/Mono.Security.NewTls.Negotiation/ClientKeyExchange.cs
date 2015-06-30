using System;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Negotiation
{
	using Handshake;

	class ClientKeyExchange : NegotiationHandler
	{
		public ClientKeyExchange (TlsContext context)
			: base (context, NegotiationState.ClientKeyExchange)
		{
		}

		TlsCertificate certificate;
		TlsCertificateVerify certificateVerify;
		TlsClientKeyExchange keyExchange;
		TlsChangeCipherSpec cipherSpec;
		TlsFinished finished;

		public override bool CanSendAlert {
			get { return true; }
		}

		protected override bool VerifyMessage (HandshakeType type)
		{
			switch (type) {
			case HandshakeType.ClientKeyExchange:
				return keyExchange == null;
			case HandshakeType.Certificate:
				return keyExchange == null && certificate == null;
			case HandshakeType.ChanceCipherSpec:
				return keyExchange != null && cipherSpec == null;
			case HandshakeType.Finished:
				return cipherSpec != null && finished == null;
			case HandshakeType.CertificateVerify:
				return keyExchange != null && certificate != null && certificateVerify == null && finished == null;
			default:
				return false;
			}
		}

		protected override MessageStatus HandleMessage (Message message)
		{
			switch (message.Type) {
			case HandshakeType.Certificate:
				if (!UserSettings.AskForClientCertificate)
					throw new TlsException (AlertDescription.UnexpectedMessage);
				certificate = (TlsCertificate)message;
				HandleCertificate (certificate);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.ClientKeyExchange:
				if (UserSettings.RequireClientCertificate && certificate == null)
					throw new TlsException (AlertDescription.UnexpectedMessage, "Peer did not respond with a certificate.");
				keyExchange = (TlsClientKeyExchange)message;
				HandleClientKeyExchange (keyExchange);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.ChanceCipherSpec:
				if (UserSettings.RequireClientCertificate && certificateVerify == null)
					throw new TlsException (AlertDescription.UnexpectedMessage, "Missing CertificateVerify message.");
				cipherSpec = (TlsChangeCipherSpec)message;
				HandleChangeCipherSpec (cipherSpec);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.Finished:
				finished = (TlsFinished)message;
				HandleFinished (finished);
				return MessageStatus.Finished;

			case HandshakeType.CertificateVerify:
				certificateVerify = (TlsCertificateVerify)message;
				HandleCertificateVerify (certificateVerify);
				return MessageStatus.ContinueNeeded;

			default:
				throw new InvalidOperationException ();
			}
		}

		protected virtual void HandleCertificate (TlsCertificate message)
		{
			if (CertificateManager.CheckClientCertificate (Config, message.Certificates))
				PendingCrypto.ClientCertificates = message.Certificates;
		}

		protected virtual void HandleCertificateVerify (TlsCertificateVerify message)
		{
			PendingCrypto.CertificateSignature = message.Signature;

			var certificate = PendingCrypto.ClientCertificates [0];
			if (!HandshakeParameters.HandshakeMessages.VerifySignature (PendingCrypto.CertificateSignature, certificate.RSA))
				throw new TlsException (AlertDescription.HandshakeFailure);
		}

		protected virtual void HandleChangeCipherSpec (TlsChangeCipherSpec message)
		{
			Session.PendingCrypto.ReadSequenceNumber = 0;
			Session.PendingRead = true;
		}

		protected virtual void HandleClientKeyExchange (TlsClientKeyExchange message)
		{
			HandshakeParameters.KeyExchange.HandleClient (Context, message.KeyExchange);

			// Initialize Cipher Suite
			PendingCrypto.InitializeCipher ();
		}

		protected virtual void HandleFinished (TlsFinished message)
		{
			var digest = HandshakeParameters.HandshakeMessages.GetHash (Session.Read.Cipher.HandshakeHashType);
			var hash = Session.Read.Cipher.PRF.ComputeClientHash (Session.Read.MasterSecret, digest);

			// Check server prf against client prf
			if (!TlsBuffer.Compare (message.Hash, hash))
				throw new TlsException (AlertDescription.HandshakeFailure);

			Session.ClientVerifyData = hash;
		}

		protected virtual TlsFinished GenerateFinished ()
		{
			var digest = HandshakeParameters.HandshakeMessages.GetHash (Session.Read.Cipher.HandshakeHashType);
			var hash = Session.Write.Cipher.PRF.ComputeServerHash (Session.Write.MasterSecret, digest);
			Session.ServerVerifyData = hash;
			return new TlsFinished (hash);
		}

		protected override NegotiationHandler GenerateOutput (TlsMultiBuffer outgoing)
		{
			SendChangeCipherSpec (outgoing);
			SwitchToNewCipher ();

			outgoing.Add (Context.EncodeHandshakeRecord (GenerateFinished ()));

			FinishHandshake ();

			if (UserSettings.MartinHack_TriggerRenegotiationOnFinish) {
				// FIXME: HACK to force renegotiation!
				Config.UserSettings.MartinHack_TriggerRenegotiationOnFinish = false;
				outgoing.Add (Context.EncodeHandshakeRecord (new TlsHelloRequest ()));
			}

			return Context.CreateNegotiationHandler (NegotiationState.RenegotiatingServerConnection);
		}
	}
}

