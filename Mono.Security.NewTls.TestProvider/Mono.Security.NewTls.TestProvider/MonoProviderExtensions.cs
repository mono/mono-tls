using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.Interface;
using Mono.Security.Providers.NewTls;

namespace Mono.Security.NewTls.TestProvider
{
	using MonoConnectionFramework;

	class MonoProviderExtensions : IMonoProviderExtensions
	{
		MonoTlsProvider provider;
		NewTlsProvider newTls;

		public MonoProviderExtensions (MonoTlsProvider provider)
		{
			this.provider = provider;
			newTls = provider as NewTlsProvider;
		}

		#region IMonoProviderExtensions implementation

		public MonoTlsConnectionInfo GetConnectionInfo ()
		{
			;
		}

		public Task Shutdown ()
		{
			if (newTls == null)
				throw new InvalidOperationException ();
			return newTls.Shutdown ();
		}

		public System.Threading.Tasks.Task RequestRenegotiation ()
		{
			throw new NotImplementedException ();
		}

		public bool IsNewTls {
			get {
				throw new NotImplementedException ();
			}
		}

		public bool SupportsInstrumentation {
			get {
				throw new NotImplementedException ();
			}
		}

		public Exception LastError {
			get {
				throw new NotImplementedException ();
			}
		}

		public bool SupportsConnectionInfo {
			get {
				throw new NotImplementedException ();
			}
		}

		public bool SupportsRenegotiation {
			get {
				throw new NotImplementedException ();
			}
		}

		#endregion
	}
}

