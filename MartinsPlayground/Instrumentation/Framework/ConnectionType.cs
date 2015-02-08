using System;

namespace Mono.Security.Instrumentation.Framework
{
	[Flags]
	public enum ConnectionType
	{
		None = 0,

		MonoClient	= 1 << 1,
		DotNetClient	= 1 << 2,
		OpenSslClient	= 1 << 3,

		MonoServer	= 1 << 8,
		DotNetServer	= 1 << 9,
		OpenSslServer	= 1 << 10,

		ClientMask	= MonoClient | DotNetClient | OpenSslClient,
		ServerMask	= MonoServer | DotNetServer | OpenSslServer
	}
}

