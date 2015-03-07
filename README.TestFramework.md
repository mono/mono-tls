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

TestFeature:
============

The values returned by the different Test Parameter Sources may be customized by using Test Features.

They are provided via the assembly-level `[assembly: TestSuite (Type)]` attribute, which points to an instance
of `ITestConfigurationProvider`.

All features and categories specified there automatically map onto corresponding elements in the Mac GUI's Settings
Dialog.  `TestConfiguration` is the class which stores their current values in a `SettingsBag`.  All the involved
classes have XML Serialization support in the `Xamarin.AsyncTests.Framework.TestSerializer` class.

Each feature has two states - enabled or disabled - but it may be a constant value.  Such constant values are used
to probe for operating-system and/or implementation specific features.  For instance, you could check whether or
not you're on Mobile and then enable / disable tests based on that.

Tests which are disabled via features do not count towards the "ignored" count - so "ignored" basically means there
was a problem with this test.

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


Test Paths and XML Serialization
================================

Internally, the new Xamarin.AsyncTests framework is completely XML based and serializable.

The XML format is not perfect yet and it contains a lot of redundant information, but it works ...

The is this concept of a "Test Path": the test path contains the current parameterization in a
serializable form.  It is stored in each TestResult, can be stored to disk and is used by the Mac GUI
to display both the Test Suite and all its TestResults in a user-friendly tree structure, where you
can select individual test parameterizations, inspect their results and also re-run them.

Test Runners
============

For the TLS Tests, there are currently two test runner frontends:

* Mono.Security.NewTls.Console is the Console Test Runner.

By default, this will run all the tests, provide a short summary and dump the full result into TestResult.xml.
This XML file can then be loaded in the Mac GUI.

In addition to this, the console runner may also function as a server and listen for a connection from the
Mac GUI.  This connection will send XML-based commands back and forth to communicate.

Unfortunately, the Mac GUI can't directly run the tests in-process yet because it would require either a
system-installed `mono/work-newtls` Mono or a custom-built Xamarin.Mac.  However, this shouldn't be a problem
anymore once we have automated builds of that `mono/work-newtls`, so it could simply be installed in
/Library/Frameworks/Mono.framework.

* Mono.Security.NewTls.Android is the Android Test Runner.

There is no Android or iOS GUI, so this will only function in server mode and listen for connections from
the Mac GUI.

* external/web-tests/Xamarin.AsyncTests.Console is a console client tool.

All it does at the moment is connecting to a remote test server and triggering a "run everything".

The result will then be dumped into TestResult.xml.

* external/web-tests/MacUI is the MAC GUI.

At the moment, it will only automatically run the samples - you need to manually configure the server's
address and port to connect to a remote server.  This will be fixed shortly.


Last changed March 07th, 2015
Martin Baulig <martin.baulig@xamarin.com>








