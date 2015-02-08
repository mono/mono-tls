using System;
using System.Collections;

namespace Mono.Security.Instrumentation.Framework
{
	public interface ITestParameterProvider
	{
		Type Type {
			get;
		}

		string Name {
			get;
		}

		IEnumerable GetParameters (Type fixtureType);
	}
}

