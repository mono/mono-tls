using System.Collections.Generic;

namespace Mono.Security.NewTls.TestFramework
{
	public interface IClientParameters : IConnectionParameters
	{
		ICollection<CipherSuiteCode> ClientCiphers {
			get; set;
		}

		IClientCertificate ClientCertificate {
			get; set;
		}
	}
}

