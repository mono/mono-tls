using System;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Handshake
{
	internal abstract class HandshakeMessage : Message
	{
		public HandshakeMessage (HandshakeType type)
			: base (ContentType.Handshake, type)
		{
		}

		public IBufferOffsetSize EncodeMessage ()
		{
			var stream = new TlsStream ();
			stream.Write (0);
			Encode (stream);

			var length = stream.Position - 4;

			stream.Buffer [0] = (byte)Type;
			// Length as an Int24 in Network Order
			stream.Buffer[1] = (byte) (length >> 16);
			stream.Buffer[2] = (byte) (length >> 8);
			stream.Buffer[3] = (byte) length;

			stream.Finish ();

			return stream.GetRemaining ();
		}

		protected abstract void Encode (TlsStream stream);

		public static HandshakeMessage ReadMessage (TlsContext context, HandshakeType handshakeType, TlsBuffer incoming)
		{
			HandshakeMessage message;
			switch (handshakeType) {
			case HandshakeType.HelloRequest:
				message = new TlsHelloRequest ();
				break;
			case HandshakeType.ServerHello:
				return new TlsServerHello (context, incoming);
			case HandshakeType.Certificate:
				return new TlsCertificate (incoming);
			case HandshakeType.ServerHelloDone:
				message = new TlsServerHelloDone ();
				break;
			case HandshakeType.Finished:
				return new TlsFinished (incoming);
			case HandshakeType.ClientHello:
				return new TlsClientHello (context, incoming);
			case HandshakeType.ClientKeyExchange:
				return new TlsClientKeyExchange (context, incoming);
			case HandshakeType.CertificateRequest:
				return new TlsCertificateRequest (incoming);
			case HandshakeType.CertificateVerify:
				return new TlsCertificateVerify (incoming);
			case HandshakeType.ServerKeyExchange:
				return new TlsServerKeyExchange (context, incoming);
			default:
				throw new TlsException (AlertDescription.UnexpectedMessage, "Unknown server handshake message received: {0}", handshakeType);
			}

			message.Read (incoming);
			return message;
		}
	}
}

