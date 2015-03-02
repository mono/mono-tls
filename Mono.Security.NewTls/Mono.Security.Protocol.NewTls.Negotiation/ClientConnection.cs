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
			HandshakeParameters.ClientRandom = Context.Session.GetSecureRandomBytes (32);
			TlsBuffer.WriteInt32 (HandshakeParameters.ClientRandom.Buffer, 0, clientUnixTime);

			var requestedCiphers = Config.UserSettings != null ? Config.UserSettings.RequestedCiphers : null;
			if (requestedCiphers == null)
				requestedCiphers = CipherSuiteFactory.GetDefaultCiphers (Config.RequestedProtocol);
			if (requestedCiphers.Protocol != Config.RequestedProtocol)
				throw new TlsException (AlertDescription.ProtocolVersion);

			HandshakeParameters.SupportedCiphers = requestedCiphers.Clone ();

			if (Config.EnableSecureRenegotiation && !Session.SecureRenegotiation && ((Config.RenegotiationFlags & RenegotiationFlags.SendCipherSpecCode) != 0))
				HandshakeParameters.SupportedCiphers.AddSCSV ();

			if (ServerNameExtension.IsLegalHostName (Config.TargetHost))
				HandshakeParameters.RequestedExtensions.Add (new ServerNameExtension (Config.TargetHost));
			if (Config.EnableSecureRenegotiation && (Session.SecureRenegotiation || ((Config.RenegotiationFlags & RenegotiationFlags.SendClientHelloExtension) != 0)))
				HandshakeParameters.RequestedExtensions.Add (RenegotiationExtension.CreateClient (Context));
			if (UserSettings.HasClientCertificateParameters)
				HandshakeParameters.RequestedExtensions.Add (new SignatureAlgorithmsExtension (UserSettings.ClientCertificateParameters.SignatureAndHashAlgorithms));

			return new TlsClientHello (
				Config.RequestedProtocol, HandshakeParameters.ClientRandom, HandshakeParameters.SessionId,
				HandshakeParameters.SupportedCiphers.ToArray (), HandshakeParameters.RequestedExtensions);
		}

		protected override NegotiationHandler GenerateOutput (TlsMultiBuffer outgoing)
		{
			StartHandshake ();
			outgoing.Add (Context.EncodeHandshakeRecord (GenerateClientHello ()));
			return Context.CreateNegotiationHandler (NegotiationState.ServerHello);
		}
	}
}

