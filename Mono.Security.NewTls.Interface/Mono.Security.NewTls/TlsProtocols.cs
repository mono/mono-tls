using System;

namespace Mono.Security.NewTls
{
	[Flags]
	public enum TlsProtocols
	{
		None		= 0,

		Tls10Server	= 0x0040,
		Tls10Client	= 0x0080,
		Tls10		= (Tls10Server|Tls10Client),

		Tls11Server	= 0x0100,
		Tls11Client	= 0x0200,
		Tls11		= (Tls11Server|Tls11Client),

		Tls12Server	= 0x0400,
		Tls12Client	= 0x0800,
		Tls12		= (Tls12Server|Tls12Client),

		ServerMask	= (Tls10Server|Tls11Server|Tls12Server),
		ClientMask	= (Tls10Client|Tls11Client|Tls12Client)
	}
}

