using System;
using System.Collections.Generic;

namespace Mono.Security.NewTls.Instrumentation
{
	using Negotiation;

	public class InstrumentCollection
	{
		ContextInstrument context;

		public bool IsEmpty {
			get { return context == null || context.IsEmpty; }
		}

		public ContextInstrument Context {
			get {
				if (context == null)
					context = new ContextInstrument ();
				return context;
			}
		}

		internal void Add (NegotiationState state, NegotiationHandlerFactory factory)
		{
			Context.Add (state, factory);
		}
	}
}

