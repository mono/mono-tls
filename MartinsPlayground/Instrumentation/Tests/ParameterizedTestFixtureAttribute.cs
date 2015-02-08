using System;
using System.Collections.Generic;

namespace Mono.Security.Instrumentation.Tests
{
	[AttributeUsage (AttributeTargets.Class, AllowMultiple=false, Inherited=true)]
	public class ParameterizedTestFixtureAttribute : Attribute
	{
		public Type Type {
			get;
			private set;
		}

		public string FactoryName {
			get;
			private set;
		}

		public ParameterizedTestFixtureAttribute (Type type, string factoryName = null)
		{
			Type = type;
			FactoryName = factoryName;
		}

		public string Category {
			get; set;
		}

		public IList<string> Categories {
			get { return Category == null ? null : Category.Split (','); }
		}

		public bool Ignore {
			get; set;
		}

		string ignoreReason;

		public string IgnoreReason {
			get { return ignoreReason; }
			set {
				ignoreReason = value;
				Ignore = !string.IsNullOrEmpty (ignoreReason);
			}
		}
	}
}

