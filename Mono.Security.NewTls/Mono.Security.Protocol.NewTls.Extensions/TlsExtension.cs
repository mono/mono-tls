using System;

namespace Mono.Security.Protocol.NewTls.Extensions
{
	public abstract class TlsExtension
	{
		public abstract ExtensionType ExtensionType {
			get;
		}

		public abstract void Encode (TlsBuffer buffer);

		public abstract bool ProcessClient (TlsContext context);

		public abstract TlsExtension ProcessServer (TlsContext context);
	}
}

