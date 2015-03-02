using System;

namespace Mono.Security.NewTls
{
	[Flags]
	public enum RenegotiationFlags
	{
		DisallowRenegotiation		= 1,
		SecureRenegotiation		= 2,

		SendClientHelloExtension	= 16,
		SendCipherSpecCode		= 32,

		AbortHandshakeIfUnsupported	= 64,
		AbortOnHelloRequest		= 128
	}
}
