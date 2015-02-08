using System;
using System.Collections;
using System.Collections.Generic;
using NUnit.Core;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;

	public class ParameterizedTestFixture<T> : NUnitTestFixture
	{
		public TestConfiguration Configuration {
			get;
			private set;
		}

		public T Parameter {
			get;
			private set;
		}

		public ParameterizedTestFixture (Type type, TestConfiguration config, T parameter)
			: base (type, new object[] { config, parameter })
		{
			Configuration = config;
			Parameter = parameter;
			TestName.FullName = string.Format ("{0}({1})", TestName.Name, parameter);
		}
	}
}

