using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;
using Mono.Security.NewTls.TestFramework;

namespace Mono.Security.Instrumentation.Framework
{
	using Framework;

	public class MonoServerParameters : ServerParameters, IMonoServerParameters
	{
		public MonoServerParameters (string identifier, IServerCertificate certificate)
			: base (identifier, certificate)
		{
		}

		public InstrumentCollection ServerInstrumentation {
			get; set;
		}
	}
}

