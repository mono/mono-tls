namespace Mono.Security.Instrumentation.Framework
{
	public class ConnectionParameters : IConnectionParameters
	{
		bool verifyPeerCertificate = true;

		public bool VerifyPeerCertificate {
			get { return verifyPeerCertificate; }
			set { verifyPeerCertificate = value; }
		}

		public bool EnableDebugging {
			get; set;
		}

		public CertificateAsPEM TrustedCA {
			get; set;
		}
	}
}

