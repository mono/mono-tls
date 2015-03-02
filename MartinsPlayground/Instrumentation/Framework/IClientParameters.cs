using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;

namespace Mono.Security.Instrumentation.Framework
{
	public interface IClientParameters : IConnectionParameters
	{
		CipherSuiteCollection ClientCiphers {
			get; set;
		}

		CertificateAndKeyAsPFX ClientCertificate {
			get; set;
		}
	}
}

