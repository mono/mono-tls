using System.Collections.Generic;

namespace Mono.Security.NewTls.TestFramework
{
	public class ServerParameters : ConnectionParameters, IServerParameters
	{
		bool askForCert;
		bool requireCert;

		public IServerCertificate ServerCertificate {
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

		public ICollection<CipherSuiteCode> ServerCiphers {
			get; set;
		}
	}
}

