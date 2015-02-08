using System;

namespace Mono.Security.Protocol.NewTls.Negotiation
{
	public enum NegotiationState
	{
		InitialClientConnection,
		RenegotiatingClientConnection,
		ClientKeyExchange,
		InitialServerConnection,
		RenegotiatingServerConnection,
		ServerFinished,
		ServerHello
	}
}

