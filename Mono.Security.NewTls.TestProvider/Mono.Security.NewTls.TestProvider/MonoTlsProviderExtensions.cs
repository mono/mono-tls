using System;
using System.Threading;
using System.Threading.Tasks;
using Mono.Security.Interface;
using Mono.Security.Providers.NewTls;

namespace Mono.Security.NewTls.TestProvider
{
	using MonoConnectionFramework;

	class MonoTlsProviderExtensions : IMonoTlsProviderExtensions
	{
		MonoTlsProvider provider;
		NewTlsProvider newTls;

		public MonoTlsProviderExtensions (MonoTlsProvider provider)
		{
			this.provider = provider;
			global::System.Console.WriteLine ("PROVIDER: {0} {1}", provider.ID, provider);
			newTls = provider as NewTlsProvider;
		}

		public MonoTlsProvider Object {
			get { return provider; }
		}

		public bool IsNewTls {
			get { return newTls != null; }
		}

		public bool SupportsMonoExtensions {
			get { return newTls != null; }
		}

		public MonoTlsConnectionInfo GetConnectionInfo ()
		{
			throw new NotImplementedException ();
		}

		public bool SupportsInstrumentation {
			get { return newTls != null; }
		}
	}
}

