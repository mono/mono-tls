using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Mono.Security.Protocol.NewTls;
using NUnit.Framework;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;
	using Resources;

	[ParameterizedTestFixture (typeof (ClientAndServerFactory))]
	public abstract class ConnectionTest
	{
		public TestConfiguration Configuration {
			get;
			private set;
		}

		public ClientAndServerFactory Factory {
			get;
			private set;
		}

		[TestFixtureSetUp]
		public virtual void FixtureSetUp ()
		{
			;
		}

		[TestFixtureTearDown]
		public virtual void FixtureTearDown ()
		{
			;
		}

		public ConnectionTest (TestConfiguration config, ClientAndServerFactory factory)
		{
			Configuration = config;
			Factory = factory;
		}
	}
}

