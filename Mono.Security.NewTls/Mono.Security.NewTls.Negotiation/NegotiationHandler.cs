using System;

namespace Mono.Security.NewTls.Negotiation
{
	using Cipher;
	using Handshake;

	abstract class NegotiationHandler
	{
		public NegotiationState State {
			get;
			private set;
		}

		public TlsContext Context {
			get;
			private set;
		}

		public Session Session {
			get { return Context.Session; }
		}

		protected CryptoParameters PendingCrypto {
			get { return Session.PendingCrypto; }
		}

		public TlsConfiguration Config {
			get { return Context.Configuration; }
		}

		protected SettingsProvider Settings {
			get { return Context.SettingsProvider; }
		}

		protected HandshakeParameters HandshakeParameters {
			get { return Context.HandshakeParameters; }
		}

		protected NegotiationHandler (TlsContext context, NegotiationState state)
		{
			Context = context;
			State = state;
		}

		protected enum MessageStatus {
			CredentialsNeeded,
			Renegotiate,
			ContinueNeeded,
			IgnoreMessage,
			GenerateOutput,
			Finished
		}

		bool hasPendingOutput;

		public abstract bool CanSendAlert {
			get;
		}

		protected abstract bool VerifyMessage (HandshakeType type);

		protected abstract MessageStatus HandleMessage (Message message);

		protected virtual bool HasPendingOutput {
			get { return hasPendingOutput; }
		}

		protected abstract NegotiationHandler GenerateOutput (TlsMultiBuffer outgoing);

		protected virtual HandshakeMessage CreateMessage (HandshakeType type, TlsBuffer incoming)
		{
			return HandshakeMessage.ReadMessage (Context, type, incoming);
		}

		public bool ProcessHandshakeMessage (HandshakeType type, TlsBuffer incoming, out SecurityStatus status)
		{
			if (HasPendingOutput && type != HandshakeType.HelloRequest)
				throw new TlsException (AlertDescription.InternalError);
			if (!VerifyMessage (type))
				throw new TlsException (AlertDescription.UnexpectedMessage);

			var incomingBuffer = new BufferOffsetSize (incoming.Buffer, incoming.Position - 4, incoming.Remaining + 4);

			var startPosition = incoming.Position - 4;
			var message = CreateMessage (type, incoming);
			incoming.Position = startPosition;

			#if DEBUG_FULL
			if (Context.EnableDebugging)
				DebugHelper.WriteLine ("ProcessMessage: {0} {1} {2}", GetType ().Name, Context.IsServer, type);
			#endif

			#if INSTRUMENTATION
			if (State == NegotiationState.InitialServerConnection && Context.HasInstrument (ConnectionInstrumentType.CloseServerConnection)) {
				DebugHelper.WriteLine ("Instrumentation requested to close server connection.");
				status = SecurityStatus.InvalidHandle;
				return true;
			}
			#endif

 			var result = HandleMessage (message);

			switch (result) {
			case MessageStatus.CredentialsNeeded:
				status = SecurityStatus.CredentialsNeeded;
				return false;

			case MessageStatus.Finished:
				hasPendingOutput = true;
				if (Context.IsServer)
					Context.HandshakeParameters.HandshakeMessages.Add (message, incomingBuffer);
				status = SecurityStatus.OK;
				return true;

			case MessageStatus.IgnoreMessage:
				status = SecurityStatus.ContinueNeeded;
				return false;

			case MessageStatus.Renegotiate:
				hasPendingOutput = true;
				if (message.Type != HandshakeType.HelloRequest)
					Context.HandshakeParameters.HandshakeMessages.Add (message, incomingBuffer);
				status = SecurityStatus.Renegotiate;
				return true;

			case MessageStatus.GenerateOutput:
				hasPendingOutput = true;
				Context.HandshakeParameters.HandshakeMessages.Add (message, incomingBuffer);
				status = SecurityStatus.ContinueNeeded;
				return true;

			case MessageStatus.ContinueNeeded:
				Context.HandshakeParameters.HandshakeMessages.Add (message, incomingBuffer);
				status = SecurityStatus.ContinueNeeded;
				return false;

			default:
				throw new InvalidOperationException ();
			}
		}

		public NegotiationHandler GenerateReply (TlsMultiBuffer outgoing)
		{
			if (!HasPendingOutput)
				throw new TlsException (AlertDescription.InternalError);

			hasPendingOutput = false;
			return GenerateOutput (outgoing);
		}

		public SecurityStatus ProcessMessage (Message message)
		{
			#if DEBUG_FULL
			if (Context.EnableDebugging)
				DebugHelper.WriteLine ("ProcessMessage: {0} {1} {2}", GetType ().Name, Context.IsServer, message);
			#endif

			if (!VerifyMessage (message.Type))
				throw new TlsException (AlertDescription.UnexpectedMessage);

			var status = HandleMessage (message);

			switch (status) {
			case MessageStatus.CredentialsNeeded:
				return SecurityStatus.CredentialsNeeded;
			case MessageStatus.Finished:
				return SecurityStatus.OK;
			case MessageStatus.ContinueNeeded:
				return SecurityStatus.ContinueNeeded;
			default:
				throw new TlsException (AlertDescription.InternalError);
			}
		}

		#region Private Methods

		protected void StartHandshake ()
		{
			if (Context.HandshakeParameters != null)
				throw new InvalidOperationException ();

			Context.HandshakeParameters = new HandshakeParameters ();
			Context.HandshakeParameters.HandshakeMessages = new HandshakeHash ();
		}

		protected void FinishHandshake ()
		{
			Context.FinishHandshake ();
		}

		protected void SendChangeCipherSpec (TlsMultiBuffer messages)
		{
			// send the chnage cipher spec.
			messages.Add (Context.EncodeRecord (ContentType.ChangeCipherSpec, new BufferOffsetSize (new byte[] { 1 })));

			Session.PendingCrypto.WriteSequenceNumber = 0;
			Session.PendingWrite = true;
		}

		protected void SwitchToNewCipher ()
		{
			// Clear old crypto params ...
			if (Session.CurrentCrypto != null)
				Session.CurrentCrypto.Dispose ();

			// ... and make the pendings ones active.
			Session.CurrentCrypto = Session.PendingCrypto;
			Session.PendingCrypto = null;

			Session.PendingRead = Session.PendingWrite = false;
		}

		#endregion
	}
}

