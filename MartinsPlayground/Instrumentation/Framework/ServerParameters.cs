using Mono.Security.Protocol.NewTls;
using Mono.Security.Protocol.NewTls.Cipher;

namespace Mono.Security.Instrumentation.Framework
{
	public class ServerParameters : ConnectionParameters, IServerParameters
	{
		bool askForCert;
		bool requireCert;

		public ServerCertificate ServerCertificate {
			get; set;
		}

		public bool AskForClientCertificate {
			get { return askForCert || requireCert; }
			set { askForCert = value; }
		}

		public bool RequireClientCertificate {
			get { return requireCert; }
			set {
				requireCert = value;
				if (value)
					askForCert = true;
			}
		}

		public CipherSuiteCollection ServerCiphers {
			get; set;
		}
	}
}

