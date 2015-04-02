using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.TestFramework
{
	public sealed class ServerParameters : ConnectionParameters, IServerParameters, ICloneable
	{
		bool askForCert;
		bool requireCert;

		public ServerParameters (string identifier, IServerCertificate certificate)
			: base (identifier)
		{
			ServerCertificate = certificate;
		}

		ServerParameters (ServerParameters other)
			: base (other)
		{
			ServerCertificate = other.ServerCertificate;
			askForCert = other.askForCert;
			requireCert = other.requireCert;
			if (other.ServerCiphers != null)
				ServerCiphers = new List<CipherSuiteCode> (other.ServerCiphers);
			ExpectedCipher = other.ExpectedCipher;
		}

		object ICloneable.Clone ()
		{
			return DeepClone ();
		}

		public ServerParameters DeepClone ()
		{
			return new ServerParameters (this);
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

		public ICollection<CipherSuiteCode> ServerCiphers {
			get; set;
		}

		public CipherSuiteCode? ExpectedCipher {
			get; set;
		}
	}
}

