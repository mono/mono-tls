using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;

namespace Mono.Security.Instrumentation.Framework
{
	using Framework;

	public class MonoClientParameters : ClientParameters, IMonoClientParameters
	{
		public ClientCertificateParameters ClientCertificateParameters {
			get; set;
		}

		public InstrumentCollection ClientInstrumentation {
			get; set;
		}
	}
}

