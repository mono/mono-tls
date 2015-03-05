using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	using Framework;

	public class MonoClientParameters : ClientParameters, IMonoClientParameters
	{
		public MonoClientParameters (string identifier)
			: base (identifier)
		{
		}

		public ClientCertificateParameters ClientCertificateParameters {
			get; set;
		}

		public InstrumentCollection ClientInstrumentation {
			get; set;
		}
	}
}

