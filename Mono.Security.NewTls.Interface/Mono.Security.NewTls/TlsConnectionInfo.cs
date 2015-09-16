using System;

namespace Mono.Security.NewTls
{
	public class TlsConnectionInfo
	{
		public CipherSuiteCode CipherSuiteCode {
			get; set;
		}

		public TlsProtocols ProtocolVersion {
			get; set;
		}

		public override string ToString ()
		{
			return string.Format ("[TlsConnectionInfo: {0}:{1}]", ProtocolVersion, CipherSuiteCode);
		}
	}
}

