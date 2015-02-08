using System;

namespace Mono.Security.Instrumentation.Framework
{
	public interface IConnectionParameters
	{
		bool VerifyPeerCertificate {
			get; set;
		}

		bool EnableDebugging {
			get; set;
		}

		CertificateAsPEM TrustedCA {
			get; set;
		}
	}
}

