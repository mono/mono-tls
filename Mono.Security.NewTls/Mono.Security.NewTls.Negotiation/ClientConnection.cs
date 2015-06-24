using System;
using System.Collections.Generic;

namespace Mono.Security.NewTls.Negotiation
{
	using Handshake;
	using Extensions;
	using Cipher;

	class ClientConnection : NegotiationHandler
	{
		public bool Renegotiating {
			get;
			private set;
		}

		public ClientConnection (TlsContext context, bool renegotiating)
			: base (context, renegotiating ? NegotiationState.RenegotiatingClientConnection : NegotiationState.InitialClientConnection)
		{
			Renegotiating = renegotiating;
		}

		protected override bool VerifyMessage (HandshakeType type)
		{
			return type == HandshakeType.HelloRequest;
		}

		protected override bool HasPendingOutput {
			get { return true; }
		}

		protected override MessageStatus HandleMessage (Message message)
		{
			if (message.Type != HandshakeType.HelloRequest)
				throw new TlsException (AlertDescription.UnexpectedMessage);

			var flags = Config.RenegotiationFlags;
			if ((flags & RenegotiationFlags.AbortOnHelloRequest) != 0)
				throw new TlsException (AlertDescription.HandshakeFailure, "Renegotiation not allowed.");

			HandleHelloRequest ((TlsHelloRequest)message);

			if ((flags & RenegotiationFlags.DisallowRenegotiation) != 0) {
				// Silently discard the request.
				return MessageStatus.Finished;
			}

			// We do not have an initial connection yet, simply ignore the message.
			if (!Renegotiating)
				return MessageStatus.IgnoreMessage;

			// Ok, we allow the request.
			if (Session.SecureRenegotiation)
				return MessageStatus.Renegotiate;

			// Silently discard it.
			return MessageStatus.IgnoreMessage;
		}

		protected virtual void HandleHelloRequest (TlsHelloRequest message)
		{
		}

		protected virtual TlsClientHello GenerateClientHello ()
		{
			var clientUnixTime = HandshakeParameters.GetUnixTime ();
			TlsBuffer.WriteInt32 (HandshakeParameters.ClientRandom.Buffer, 0, clientUnixTime);

			if (ServerNameExtension.IsLegalHostName (Config.TargetHost))
				HandshakeParameters.RequestedExtensions.Add (new ServerNameExtension (Config.TargetHost));
			if (Config.EnableSecureRenegotiation && (Session.SecureRenegotiation || ((Config.RenegotiationFlags & RenegotiationFlags.SendClientHelloExtension) != 0)))
				HandshakeParameters.RequestedExtensions.Add (RenegotiationExtension.CreateClient (Context));

			var signatureParameters = Context.ConfigurationProvider.ClientSignatureParameters;
			if (signatureParameters != null) {
				Session.SignatureParameters = signatureParameters;
				Context.SignatureProvider.VerifySignatureParameters (Context, signatureParameters);
				HandshakeParameters.RequestedExtensions.Add (new SignatureAlgorithmsExtension (signatureParameters));
			}

			return new TlsClientHello (
				Config.RequestedProtocol, HandshakeParameters.ClientRandom, HandshakeParameters.SessionId,
				HandshakeParameters.SupportedCiphers.ToArray (), HandshakeParameters.RequestedExtensions);
		}

		protected virtual void Resolve ()
		{
			HandshakeParameters.ClientRandom = Context.Session.GetSecureRandomBytes (32);

			var requestedUserCiphers = Config.UserSettings != null ? Config.UserSettings.RequestedCiphers : null;
			CipherSuiteCollection requestedCiphers;
			if (requestedUserCiphers != null)
				requestedCiphers = new CipherSuiteCollection (Config.RequestedProtocol, requestedUserCiphers);
			else
				requestedCiphers = CipherSuiteFactory.GetDefaultCiphers (Config.RequestedProtocol);
			if (requestedCiphers.Protocol != Config.RequestedProtocol)
				throw new TlsException (AlertDescription.ProtocolVersion);

			HandshakeParameters.SupportedCiphers = requestedCiphers.Clone ();

			if (Config.RequestedProtocol == TlsProtocolCode.Tls12 && !UserSettings.HasClientCertificateParameters)
				UserSettings.ClientCertificateParameters = ClientCertificateParameters.GetDefaultParameters ();

			if (Config.EnableSecureRenegotiation && !Session.SecureRenegotiation && ((Config.RenegotiationFlags & RenegotiationFlags.SendCipherSpecCode) != 0))
				HandshakeParameters.SupportedCiphers.AddSCSV ();

			Context.Session.SignatureParameters = Context.SignatureProvider.GetClientSignatureParameters (Context);
			if (Context.Session.SignatureParameters != null)
				Context.SignatureProvider.VerifySignatureParameters (Context, Context.Session.SignatureParameters);
		}

		protected override NegotiationHandler GenerateOutput (TlsMultiBuffer outgoing)
		{
			StartHandshake ();

			Resolve ();

			outgoing.Add (Context.EncodeHandshakeRecord (GenerateClientHello ()));
			return Context.CreateNegotiationHandler (NegotiationState.ServerHello);
		}
	}
}

