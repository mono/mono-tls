using Mono.Security.NewTls;
using Mono.Security.NewTls.Instrumentation;

namespace Mono.Security.Instrumentation.Framework
{
	using Framework;

	public class MonoClientAndServerParameters : ClientAndServerParameters, IMonoClientAndServerParameters
	{
		public MonoClientAndServerParameters (string identifier)
			: base (identifier)
		{
		}

		public ClientCertificateParameters ClientCertificateParameters {
			get; set;
		}

		InstrumentCollection clientInstrumentation;
		InstrumentCollection serverInstrumentation;

		public InstrumentCollection ClientInstrumentation {
			get {
				if (clientInstrumentation == null)
					clientInstrumentation = new InstrumentCollection ();
				return clientInstrumentation;
			}
		}

		public InstrumentCollection ServerInstrumentation {
			get {
				if (serverInstrumentation == null)
					serverInstrumentation = new InstrumentCollection ();
				return serverInstrumentation;
			}
		}
	}
}

