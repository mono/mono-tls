using System;
using System.Linq;
using System.Collections.Generic;

namespace Mono.Security.Instrumentation.Framework
{
	public class TestConfiguration
	{
		TestConfiguration ()
		{
		}

		static readonly TestConfiguration instance = new TestConfiguration ();

		public static TestConfiguration DangerousGetInstance ()
		{
			return instance;
		}

		public bool EnableDebugging {
			get; set;
		}

		List<ITestParameterProvider> parameterProviders = new List<ITestParameterProvider> ();

		public ITestParameterProvider GetProvider (Type type)
		{
			return parameterProviders.Find (p => p.Type.Equals (type));
		}

		public ITestParameterProvider GetProvider (string name)
		{
			return parameterProviders.Find (p => name.Equals (p.Name));
		}

		public void RegisterProvider (ITestParameterProvider provider)
		{
			parameterProviders.Add (provider);
		}
	}
}

