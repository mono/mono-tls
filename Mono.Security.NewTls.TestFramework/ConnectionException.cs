using System;

namespace Mono.Security.NewTls.TestFramework
{
	public class ConnectionException : Exception
	{
		public ConnectionException (string message, params object[] args)
			: base (string.Format (message, args))
		{
		}
	}
}

