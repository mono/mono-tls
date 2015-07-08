using System;

namespace Mono.Security.NewTls.Negotiation
{
	using Handshake;

	class ServerFinished : NegotiationHandler
	{
		public ServerFinished (TlsContext context)
			: base (context, NegotiationState.ServerFinished)
		{
		}

		TlsChangeCipherSpec changeCipher;
		TlsFinished finished;

		public override bool CanSendAlert {
			get { return true; }
		}

		protected override bool VerifyMessage (HandshakeType type)
		{
			switch (type) {
			case HandshakeType.ChanceCipherSpec:
				return changeCipher == null;
			case HandshakeType.Finished:
				return changeCipher != null && finished == null;
			default:
				return false;
			}
		}

		protected override MessageStatus HandleMessage (Message message)
		{
			switch (message.Type) {
			case HandshakeType.ChanceCipherSpec:
				changeCipher = (TlsChangeCipherSpec)message;
				HandleChangeCipherSpec (changeCipher);
				return MessageStatus.ContinueNeeded;

			case HandshakeType.Finished:
				finished = (TlsFinished)message;
				HandleFinished (finished);
				return MessageStatus.Finished;

			default:
				throw new InvalidOperationException ();
			}
		}

		protected virtual void HandleChangeCipherSpec (TlsChangeCipherSpec message)
		{
			PendingCrypto.ReadSequenceNumber = 0;
			SwitchToNewCipher ();
		}

		protected virtual void HandleFinished (TlsFinished message)
		{
			var digest = HandshakeParameters.HandshakeMessages.GetHash (Session.Write.Cipher.HandshakeHashType);
			var hash = Session.Write.Cipher.PRF.ComputeServerHash (Session.Write.MasterSecret, digest);

			// Check server prf against client prf
			if (!TlsBuffer.Compare (message.Hash, hash))
				throw new TlsException (AlertDescription.HandshakeFailure);

			Session.ServerVerifyData = hash;

			FinishHandshake ();
		}

		protected override NegotiationHandler GenerateOutput (TlsMultiBuffer outgoing)
		{
			return Context.CreateNegotiationHandler (NegotiationState.RenegotiatingClientConnection);
		}
	}
}

