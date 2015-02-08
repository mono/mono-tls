using System;
using System.Collections.Generic;

namespace Mono.Security.Instrumentation.Framework
{
	public interface IConnectionFactoryProvider : ITestParameterProvider
	{
		IEnumerable<ConnectionFactory> Factories {
			get;
		}
	}
}

