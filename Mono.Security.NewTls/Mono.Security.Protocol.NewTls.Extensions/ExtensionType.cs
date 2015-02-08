using System;

namespace Mono.Security.Protocol.NewTls.Extensions
{
	public enum ExtensionType : short
	{
		ServerName		= 0x0000,
		SignatureAlgorithms	= 0x000d,
		Renegotiation		= unchecked ((short)0xff01)
	}
}
