using System;

namespace Mono.Security.NewTls
{
	public class TlsConnectionInfo
	{
		public CipherSuiteCode CipherCode {
			get; set;
		}

		public TlsProtocols ProtocolVersion {
			get; set;
		}
	}
}

