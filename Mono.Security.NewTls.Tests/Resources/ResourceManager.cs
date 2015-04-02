using System;
using System.IO;
using System.Reflection;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	public static class ResourceManager
	{
		static LocalCACertificate cacert;
		static SelfSignedServerCertificate selfServer;
		static ServerCertificateFromCA serverCert;
		static MonkeyCertificate monkeyCert;

		static ResourceManager ()
		{
			cacert = new LocalCACertificate ();
			selfServer = new SelfSignedServerCertificate ();
			serverCert = new ServerCertificateFromCA ();
			monkeyCert = new MonkeyCertificate ();
		}

		public static LocalCACertificate LocalCACertificate {
			get { return cacert; }
		}

		public static IServerCertificate SelfSignedServerCertificate {
			get { return selfServer; }
		}

		public static IServerCertificate ServerCertificateFromCA {
			get { return serverCert; }
		}

		public static IServerCertificate DefaultServerCertificate {
			get { return serverCert; }
		}

		public static IClientCertificate MonkeyCertificate {
			get { return monkeyCert; }
		}

		internal static byte[] ReadResource (string name)
		{
			var assembly = typeof(ResourceManager).GetTypeInfo ().Assembly;
			using (var stream = assembly.GetManifestResourceStream (assembly.GetName ().Name + "." + name)) {
				var data = new byte [stream.Length];
				var ret = stream.Read (data, 0, data.Length);
				if (ret != data.Length)
					throw new IOException ();
				return data;
			}
		}
	}
}

