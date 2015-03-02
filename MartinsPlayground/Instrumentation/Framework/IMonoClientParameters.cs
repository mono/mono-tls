using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;

namespace Mono.Security.Instrumentation.Framework
{
	using Framework;

	public interface IMonoClientParameters : IClientParameters
	{
		ClientCertificateParameters ClientCertificateParameters {
			get; set;
		}

		InstrumentCollection ClientInstrumentation {
			get;
		}
	}
}

