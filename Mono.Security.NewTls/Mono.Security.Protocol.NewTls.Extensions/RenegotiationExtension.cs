using System;

namespace Mono.Security.Protocol.NewTls.Extensions
{
	public class RenegotiationExtension : TlsExtension
	{
		public override ExtensionType ExtensionType {
			get { return ExtensionType.Renegotiation; }
		}

		public SecureBuffer Data {
			get;
			private set;
		}

		internal RenegotiationExtension (TlsBuffer incoming)
		{
			Data = new SecureBuffer (incoming.ReadBytes (incoming.ReadByte ()));
		}

		RenegotiationExtension (SecureBuffer data)
		{
			Data = data;
		}

		internal static RenegotiationExtension CreateImplicit ()
		{
			return new RenegotiationExtension ((SecureBuffer)null);
		}

		internal static RenegotiationExtension CreateClient (TlsContext context)
		{
			if (!context.Session.SecureRenegotiation && (context.Configuration.RenegotiationFlags & RenegotiationFlags.SendClientHelloExtension) == 0)
				return null;

			context.HandshakeParameters.RequestedSecureNegotiation = true;
			return new RenegotiationExtension (context.Session.ClientVerifyData);
		}

		public override void Encode (TlsBuffer buffer)
		{
			var size = Data != null ? Data.Size : 0;
			buffer.Write ((short)ExtensionType);
			buffer.Write ((short)(size + 1));
			buffer.Write ((byte)size);
			if (Data != null)
				buffer.Write (Data.Buffer);
		}

		public override bool ProcessClient (TlsContext context)
		{
			if (context.IsServer)
				throw new InvalidOperationException ();

			if (!context.HandshakeParameters.RequestedSecureNegotiation)
				throw new TlsException (AlertDescription.HandshakeFailure);

			if (!context.Session.SecureRenegotiation) {
				// Initial handshake
				if (Data != null)
					throw new TlsException (AlertDescription.HandshakeFailure);
				context.HandshakeParameters.SecureNegotiationSupported = true;
				return true;
			}

			var clientData = context.Session.ClientVerifyData;
			var serverData =  context.Session.ServerVerifyData;
			DebugHelper.WriteLine ("CHECKING CLIENT DATA", clientData);
			DebugHelper.WriteLine ("CHECKING SERVER DATA", serverData);
			DebugHelper.WriteLine ("CHECKING WHAT WE GOT", Data);
			var expectedLength = clientData.Size + serverData.Size;
			if (Data.Size != expectedLength)
				throw new TlsException (AlertDescription.DecodeError);

			if (!TlsBuffer.Compare (clientData.Buffer, 0, clientData.Size, Data.Buffer, 0, clientData.Size))
				throw new TlsException (AlertDescription.HandshakeFailure);
			if (!TlsBuffer.Compare (serverData.Buffer, 0, serverData.Size, Data.Buffer, clientData.Size, serverData.Size))
				throw new TlsException (AlertDescription.HandshakeFailure);

			context.HandshakeParameters.SecureNegotiationSupported = true;
			return true;
		}

		public override TlsExtension ProcessServer (TlsContext context)
		{
			if (!context.IsServer)
				throw new InvalidOperationException ();

			if (context.Session.SecureRenegotiation) {
				if (!TlsBuffer.Compare (context.Session.ClientVerifyData, Data))
					throw new TlsException (AlertDescription.HandshakeFailure);
			} else {
				if (Data != null && Data.Size != 0)
					throw new TlsException (AlertDescription.HandshakeFailure);
				context.HandshakeParameters.RequestedSecureNegotiation = true;
				context.HandshakeParameters.SecureNegotiationSupported = true;
				context.Session.SecureRenegotiation = true;
				return new RenegotiationExtension (new SecureBuffer (0));
			}

			var clientData = context.Session.ClientVerifyData;
			var serverData =  context.Session.ServerVerifyData;
			DebugHelper.WriteLine ("WRITING CLIENT DATA", clientData);
			DebugHelper.WriteLine ("WRITING SERVER DATA", serverData);
			var data = new SecureBuffer (clientData.Size + serverData.Size);
			Buffer.BlockCopy (clientData.Buffer, 0, data.Buffer, 0, clientData.Size);
			Buffer.BlockCopy (serverData.Buffer, 0, data.Buffer, clientData.Size, serverData.Size);

			return new RenegotiationExtension (data);
		}
	}
}

