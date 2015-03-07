TestParameter:
==============

Test Parameters are resolved when the Test Suite is loaded.

Each value returned by ITestParameterSource<T> must have a unique ITestParameter.Value, which is a stringified
representation that will be used during serialization and displayed in the UI.

The class that implements ITestParameterSource<T> may be instantiated multiple times and GetParameters() may also
be called multiple times.  Returned values will be identified by their ITestParameter.Value identifier and returned
objects from different invocations with the same identifier will be assumed to be identical.

You may choose to ignore 'filter' - if you use it, then you must ignore any unknown filter values and treat theam as
if 'null' has been used.

The order in which multiple ITestParameterSource<T>'s are invoked can not be guaranteed - on the provided TestContext,
only CurrentCategory and IsEnabled(TestFeature) may be used.

It is very important not to store any kind of state in these attribute classes.

If any consumer of these test parameters wishes to modify the returned objects, then these must implement
Xamarin.AsyncTests.ICloneable to provide a deep copy.  GetParameters() may or may not be re-invoked on subsequent
test runs, so modifying the returned object without using ICloneable will ask for trouble.

TestHost:
=========

A Test Host is a "heavy" stateful test parameter, which may use async operations.

Let's have a look at SimpleConnectionTest:

	[AsyncTestFixture]
	public class SimpleConnectionTest
	{
		[NewTlsTestFeatures.SelectConnectionProvider]
		public ConnectionProviderType ServerType {
			get;
			private set;
		}

		[NewTlsTestFeatures.SelectConnectionProvider]
		public ConnectionProviderType ClientType {
			get;
			private set;
		}

		[AsyncTest]
		public async Task TestConnection (TestContext ctx,
			[SimpleConnectionParameter] ClientAndServerParameters parameters,
			[ServerTestHost] IServer server, [ClientTestHost] IClient client)
		{ }
	}
	
When TestConnection() is invoked, there are three test parameters and two test hosts.

First, the the class parameters 'ServerType' and 'ClientType' will iterate through all their possible
values.  The order is unspecified and their values are set via reflection.

Then, method arguments will be processed from left to right.  If any test parameters are encountered, then
each of them will iterate through all its possible values.

When a test host is instantiated, then the TestContext will contain the current value of each previously
encountered test parameter and you may use TryGetParameter<T> (out T value, string name = null) to retrieve
them.  There is also GetParameter<T> (string name = null) which will throw on error.

When used without any name, the value of the first test parameter with that type is returned, so for instance
the [ServerTestHost] may `ctx.GetParameter<ClientAndServerParameters>` to retrieve the current "parameters"
value.  Or it could use `ctx.GetParameter<ConnectionProviderType> ("ClientType")` to get that property.

You may also query for previously created tests hosts, for instance the [ClientTestHost] could use
`ctx.GetParameter<IServer>()` to get the current `IServer` instance.

The same also applies to the current fixture instance - you may either query by type, so
`ctx.GetParameter<SimpleConnectionTest> ()` in our example, or call `ctx.GetFixtureInstance()`.

Each test host may provide the four async methods from ITestInstance: Initiaze() and Destroy() are called when
the host is created / destroyed.

And there is also PreRun() and PostRun().  These come to play when any parameterizations are used after
the test host - for instance, look at this:

		[AsyncTest]
		public async Task SelectClientCipher (TestContext ctx,
			[SimpleConnectionParameter ("simple")] ClientAndServerParameters parameters,
			[ServerTestHost] IServer server,
			[SelectCipherSuite ("ClientCipher")] CipherSuiteCode clientCipher,
			[ClientTestHost] IClient client)

Here, a new `IServer` instance will be created (and their Initialize() / Destroy() being called) for each
value of `parameters` and any previous parameters.  Then `clientCiphers` will iterate though all its possible
values, reusing the same `IServer` instance - but calling PreRun() and PostRun() each time.

So the above method will create a new client for each of the different cipher suite codes, all connecting to
the same server.

And this method will create a new client and server pair for each different cipher suite code:

		[AsyncTest]
		public async Task SelectClientCipher (TestContext ctx,
			[SimpleConnectionParameter ("simple")] ClientAndServerParameters parameters,
			[SelectCipherSuite ("ClientCipher")] CipherSuiteCode clientCipher,
			[ServerTestHost] IServer server,
			[ClientTestHost] IClient client)



