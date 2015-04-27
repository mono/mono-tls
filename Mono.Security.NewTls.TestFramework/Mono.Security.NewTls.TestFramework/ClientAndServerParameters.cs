using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.TestFramework
{
	public sealed class ClientAndServerParameters : ConnectionParameters, IClientAndServerParameters, IClientParameters, IServerParameters, ICloneable
	{
		bool askForCert;
		bool requireCert;

		public ClientAndServerParameters (string identifier, IServerCertificate certificate)
			: base (identifier)
		{
			ServerCertificate = certificate;
		}

		ClientAndServerParameters (ClientAndServerParameters other)
			: base (other)
		{
			ServerCertificate = other.ServerCertificate;
			ClientCertificate = other.ClientCertificate;
			if (other.ClientCiphers != null)
				ClientCiphers = new List<CipherSuiteCode> (other.ClientCiphers);
			if (other.ServerCiphers != null)
				ServerCiphers = new List<CipherSuiteCode> (other.ServerCiphers);
			askForCert = other.askForCert;
			requireCert = other.requireCert;
			ExpectedCipher = other.ExpectedCipher;
		}

		object ICloneable.Clone ()
		{
			return DeepClone ();
		}

		IConnectionParameters ICommonConnectionParameters.ConnectionParameters {
			get { return this; }
		}

		IClientParameters IClientAndServerParameters.ClientParameters {
			get { return this; }
		}

		IServerParameters IClientAndServerParameters.ServerParameters {
			get { return this; }
		}

		public ClientAndServerParameters DeepClone ()
		{
			return new ClientAndServerParameters (this);
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

		public IClientCertificate ClientCertificate {
			get; set;
		}

		public CipherSuiteCode? ExpectedCipher {
			get; set;
		}
	}
}

