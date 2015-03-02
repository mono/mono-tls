using System;

namespace Mono.Security.NewTls
{
	[CLSCompliant (false)]
	public class TlsConnectionInfo
	{
		public CipherSuiteCode CipherCode {
			get; set;
		}
	}
}

