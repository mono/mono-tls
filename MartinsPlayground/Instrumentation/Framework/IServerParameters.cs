using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Cipher;

namespace Mono.Security.Instrumentation.Framework
{
	public interface IServerParameters : IConnectionParameters
	{
		ServerCertificate ServerCertificate {
			get; set;
		}

		bool AskForClientCertificate {
			get; set;
		}

		bool RequireClientCertificate {
			get; set;
		}

		CipherSuiteCollection ServerCiphers {
			get; set;
		}
	}
}

