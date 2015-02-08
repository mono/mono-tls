using System;

namespace Mono.Security.Instrumentation.Framework
{
	public class ConnectionException : Exception
	{
		public ConnectionException (string message, params object[] args)
			: base (string.Format (message, args))
		{
		}
	}
}

