using System;

namespace Mono.Security.Protocol.NewTls
{
	using Cipher;

	[CLSCompliant (false)]
	public class TlsConnectionInfo
	{
		public CipherSuiteCode CipherCode {
			get; set;
		}
	}
}

