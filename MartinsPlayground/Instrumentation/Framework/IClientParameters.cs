using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	public interface IClientParameters : IConnectionParameters
	{
		CipherSuiteCollection ClientCiphers {
			get; set;
		}

		ICertificateAndKeyAsPFX ClientCertificate {
			get; set;
		}
	}
}

