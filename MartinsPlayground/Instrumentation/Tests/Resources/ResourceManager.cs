using System;
using System.IO;
using System.Reflection;
using Mono.Security.NewTls.TestProvider;

namespace Mono.Security.Instrumentation.Resources
{
	using Framework;

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

		public static ServerCertificate SelfSignedServerCertificate {
			get { return selfServer; }
		}

		public static ServerCertificate ServerCertificateFromCA {
			get { return serverCert; }
		}

		public static ServerCertificate DefaultServerCertificate {
			get { return serverCert; }
		}

		public static ClientCertificate MonkeyCertificate {
			get { return monkeyCert; }
		}

		internal static byte[] ReadResource (string name)
		{
			var assembly = Assembly.GetExecutingAssembly ();
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

