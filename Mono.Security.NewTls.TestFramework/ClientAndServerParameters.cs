using System.Collections.Generic;

namespace Mono.Security.NewTls.TestFramework
{
	public class ClientAndServerParameters : ConnectionParameters, IClientAndServerParameters
	{
		bool askForCert;
		bool requireCert;

		public ClientAndServerParameters (string identifier)
			: base (identifier)
		{
		}

		public ICollection<CipherSuiteCode> ClientCiphers {
			get; set;
		}

		public ICollection<CipherSuiteCode> ServerCiphers {
			get; set;
		}

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

		public ICertificateAndKeyAsPFX ClientCertificate {
			get; set;
		}
	}
}

