using System;

namespace Mono.Security.NewTls.Negotiation
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

