using System;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Handshake
{
	class TlsChangeCipherSpec : Message
	{
		public TlsChangeCipherSpec ()
			: base (ContentType.ChangeCipherSpec, HandshakeType.ChanceCipherSpec)
		{
		}

		protected override void Read (TlsBuffer incoming)
		{
			var message = incoming.ReadByte ();
			if (message != 1 || incoming.Remaining != 0)
				throw new TlsException (AlertDescription.DecodeError, "Received invalid ChangeCipherSpec message");
		}
	}
}

