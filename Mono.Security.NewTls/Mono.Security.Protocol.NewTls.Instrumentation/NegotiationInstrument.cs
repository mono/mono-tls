using System;

namespace Mono.Security.NewTls.Instrumentation
{
	using Negotiation;

	internal delegate NegotiationHandler NegotiationHandlerFactory (TlsContext context);

	public class NegotiationInstrument : Instrument
	{
		public NegotiationState State {
			get;
			private set;
		}

		internal NegotiationHandlerFactory Factory {
			get;
			private set;
		}

		internal NegotiationInstrument (NegotiationState state, NegotiationHandlerFactory factory)
		{
			State = state;
			Factory = factory;
		}
	}
}

