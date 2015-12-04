using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.Interface;
using Mono.Security.Providers.NewTls;

namespace Mono.Security.NewTls.TestProvider
{
	using MonoConnectionFramework;

	class MonoSslStreamExtensions : IMonoSslStreamExtensions
	{
		MonoNewTlsStream stream;

		public MonoSslStreamExtensions (MonoNewTlsStream stream)
		{
			this.stream = stream;
		}

		public IMonoSslStream Object {
			get { return stream; }
		}

		public MonoTlsConnectionInfo GetConnectionInfo ()
		{
			return stream.GetConnectionInfo ();
		}

		public Task Shutdown ()
		{
			return stream.Shutdown ();
		}

		public Task RequestRenegotiation ()
		{
			return stream.RequestRenegotiation ();
		}

		public Exception LastError {
			get { return stream.LastError; }
		}

		public bool SupportsConnectionInfo {
			get { return true; }
		}

		public bool SupportsRenegotiation {
			get { return true; }
		}
	}
}

