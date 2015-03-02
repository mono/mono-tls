using System;
using System.Collections.Generic;

namespace Mono.Security.NewTls.Instrumentation
{
	using Negotiation;

	public class ContextInstrument : Instrument
	{
		Dictionary<NegotiationState,NegotiationInstrument> negotiationInstruments;

		public ContextInstrument ()
		{
			negotiationInstruments = new Dictionary<NegotiationState, NegotiationInstrument> (); 
		}

		public bool IsEmpty {
			get { return negotiationInstruments.Count == 0; }
		}

		internal void Add (NegotiationState state, NegotiationHandlerFactory factory)
		{
			negotiationInstruments.Add (state, new NegotiationInstrument (state, factory));
		}

		internal NegotiationHandler CreateNegotiationHandler (TlsContext context, NegotiationState state)
		{
			NegotiationInstrument instrument;
			if (negotiationInstruments.TryGetValue (state, out instrument))
				return instrument.Factory (context);
			return null;
		}
	}
}

