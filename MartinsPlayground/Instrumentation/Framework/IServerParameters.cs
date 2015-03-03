using System.Collections.Generic;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	public interface IServerParameters : IConnectionParameters
	{
		IServerCertificate ServerCertificate {
			get; set;
		}

		bool AskForClientCertificate {
			get; set;
		}

		bool RequireClientCertificate {
			get; set;
		}

		ICollection<CipherSuiteCode> ServerCiphers {
			get; set;
		}
	}
}

