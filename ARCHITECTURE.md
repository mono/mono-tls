Mono.Security.Interface / Mono.Security.Providers
=================================================

This is not a public API yet, but will eventually become public.


Mono.Security.Interface
-----------------------

`Mono.Security.Interface` provides an abstraction layer for the TLS
APIs that are currently being used by Mono's class libraries.

The main API entry points are `MonoTlsProviderFactory.GetProvider()`
and `MonoTlsProviderFactory.InstallProvider()`.

Mono.Net.Security
-----------------

`Mono.Net.Security` provides the internal implementation and lives
inside `System.dll` as private and internal APIs.  There's an
internal helper class called `NoReflectionHelper`, which allows
`Mono.Security.dll` to access these without using reflection.

On Mobile, the `Mono.Security.Interface` APIs are included as public
APIs in `System.dll`.

Mono.Security.Providers
-----------------------

Implementations of the `Mono.Security.Interface.MonoTlsProvider` class
to provide TLS functionality.

The default provider is inside `System.dll` - it will be used automatically
if you don't explicitly install a custom provider, so simply call
`MonoTlsProviderFactory.GetProvider()` to use it.

* *DotNet*:
  Provides the default `SslStream` implementation from `System.dll`, only using
  public .NET types.
  
  See [mcs/class/Mono.Security.Providers.DotNet](https://github.com/mono/mono/tree/master/mcs/class/Mono.Security.Providers.DotNet).
  
  Internally, we're using an internal class called [`LegacySslStream`](https://github.com/mono/mono/blob/work-newtls/mcs/class/System/Mono.Net.Security/LegacySslStream.cs) inside `System.dll`, which is a copy of the old `SslStream` implementation.
  
* *NewSystemSource*:
  Compiles several referencesource files which would normally live inside
  `System.dll` if we compiled it with their `SslStream` implementation.
  
  This allows to keep the code in `System.dll` as-is, while still providing the
  new `SslStream`, which will be required by the new TLS code.
  
  `System.dll` needs to make its internals visible and we're using several compiler /
  external alias tricks in here to make this work.
  
  In this configuration, `MONO_SYSTEM_ALIAS`, `MONO_FEATURE_NEW_TLS` and
  `MONO_FEATURE_NEW_SYSTEM_SOURCE` (defining conditional for this configuration)
  are defined.  We do not define `MONO_X509_ALIAS here`.
  
  See [mcs/class/Mono.Security.Providers.NewSystemSource](https://github.com/mono/mono/tree/master/mcs/class/Mono.Security.Providers.NewSystemSource).
  
The `Mono.Security.Providers.DotNet` and `Mono.Security.Providers.NewSystemSource` are
currently built by default, but should only be used to test the new TLS code and be
considered stable APIs.

Reference Source and how the pieces fit together
================================================

The new TLS code requires Microsoft's `SslStream` implementation from the referencesource, the corresponding files are:

* [System/Net/SecureProtocols/SslStream.cs](https://github.com/mono/referencesource/blob/mono/System/net/System/Net/SecureProtocols/SslStream.cs)
* [System/Net/SecureProtocols/_SslStream.cs](https://github.com/mono/referencesource/blob/mono/System/net/System/Net/SecureProtocols/_SslStream.cs)
* [System/Net/SecureProtocols/_SslState.cs](https://github.com/mono/referencesource/blob/mono/System/net/System/Net/SecureProtocols/_SslState.cs)
* [System/Net/_SecureChannel.cs](https://github.com/mono/referencesource/blob/mono/System/net/System/Net/_SecureChannel.cs)

Main bridge between their code and ours is [mcs/class/System/ReferenceSources/SSPIWrapper.cs](https://github.com/mono/mono/blob/master/mcs/class/System/ReferenceSources/SSPIWrapper.cs).

All these classes are currently built into `Mono.Security.Providers.NewSystemSource.dll` instead of `System.dll` because they depend on the new TLS implementation.

Main bridge between our code and theirs is [Mono.Security.Providers.NewTls.MonoNewTlsStreamFactory](https://github.com/mono/mono-tls/blob/master/Mono.Security.Providers/NewTls/Mono.Security.Providers.NewTls/MonoNewTlsStreamFactory.cs).

The `Mono.Security.Providers.NewTls` module uses advanced `extern alias` compilation magic to create an instance of their `SslStream` class from the `Mono.Security.Providers.NewSystemSource` module (again, this uses advanced `extern alias` compilation magic).

This `Mono.Security.Providers.NewTls` module provides an implementation of [`Mono.Security.Interface.MonoTlsProvider`](https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/MonoTlsProvider.cs), which is then registered with the [`MonoTlsProviderFactory`](https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/MonoTlsProviderFactory.cs), a new public `Mono.Security.dll` (`System.dll` on Mobile) API.

When Mono's existing web-stack attempts to make a TLS call, it will query `MonoTlsProviderFactory` for the current provider, so it can use the new implementation.

Installation and hooking things up
==================================

To use the new code, you need to build the [mono-tls](https://github.com/mono/mono-tls) module.  There is a Xamarin Studio [solution](https://github.com/mono/mono-tls/blob/master/MartinsPlayground.sln) that you can use to build, see the
[OLD-README.md](https://github.com/mono/mono-tls/blob/master/OLD-README.md) for details.

If you're only interested in testing the new TLS implementation, then you don't need to build the native openssl or any
of the test pieces, so all that you need from the `MartinsPlayground.sln` are the following projects:

* `Mono.Security.NewTls`
* `Mono.Security.NewTls.Interface`
* `Mono.Security.Providers.NewTls`

HttpWebRequest abstraction
--------------------------

There are two ways of hooking things up - you can do it either per process or per request.

Per-process installation is really easy, all you need to do is call this on startup:

	MonoTlsProviderFactory.InstallProvider (new NewTlsProvider ());

This will switch to the new TLS implementation for anything that's using `HttpWebRequest`, `FtpWebRequest` or
`SmptClient`.  It does not affect `HttpListener` or direct calls to `SslStream`.

Adding the new switcher code to `HttpListener` is up for discussion and could certainly be added when needed.
It cannot be added to `SslStream` directly because doing so would defeat the entire purpose of eventually
switching over to using the Reference Source's version of it.

Alternatively, you can also specify a custom `MonoTlsProvider` for a single `HttpWebRequest`.  To do so, use
[`Mono.Security.Interface.MonoTlsProviderFactory.CreateHttpsRequest()`](https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/MonoTlsProviderFactory.cs#L105), passing the request URI, your custom `MonoTlsProvider`
instance and an optional `MonoTlsSettings` object.  Internally, this will use reflection to invoke a custom
`HttpWebRequest` [constructor](https://github.com/mono/mono/blob/master/mcs/class/System/System.Net/HttpWebRequest.cs#L164).

This approach also allows you to pass custom [`MonoTlsSettings`](https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/MonoTlsSettings.cs).

Code Sample:
------------

FIXME: needs testing!

Per-process setup:

    using System;
    using System.Net;
    using Mono.Security.Interface;
    using Mono.Security.Providers.NewTls;
	
    class X {
	    static void Main ()
	    {
		    MonoTlsProviderFactory.InstallProvider (new NewTlsProvider ());
		    var request = (HttpWebRequest) HttpWebRequest.Create ("https://www.xamarin.com/");
		    var response = request.GetResponse ();
		    Console.WriteLine (response);
	    }
    }
    

Per-request setup:

    using System;
    using System.Net;
    using Mono.Security.Interface;
    using Mono.Security.Providers.NewTls;
    
    class X {
	    static void Main ()
	    {
		    var provider = new NewTlsProvider ();
		    var uri = new Uri ("https://www.xamarin.com/")
		    var request = MonoTlsProviderFactory.CreateHttpsRequest (uri, provider);
		    var response = request.GetResponse ();
		    Console.WriteLine (response);
	    }
    }
    

Certificate validation abstraction
----------------------------------

On OS X and iOS, we cannot compute the `X509Chain` and use it for certificate validation because the operation system
does not support this.  For this reason, we are P/Invoking into a native OS-API to validate certificates on OS X, iOS
and Android - this code lives in an internal class inside `System.dll`.

This code has been cleaned up, moved into its own class and an accessor API added.  Instead of having a bunch of different
overloads with arguments that are being passed around function calls, all these options have been moved into the new
[`MonoTlsSettings`](https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/MonoTlsSettings.cs) class.
You can specify custom callbacks there as well as whether or not the `ServicePointManager`s callback should be used.

Calling [`Mono.Security.Interface.CertificateValidationHelper.GetValidator()`(https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/CertificateValidationHelper.cs#L156) gets you a `ICertificateValidator` instance, which you can use to
validate a chain or select a client certificate with the provided settings.

SslStream abstraction
---------------------

To use the general `SslStream` abstraction, call [`MonoTlsProvider.CreateSslStream()`](https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/MonoTlsProvider.cs#L102) to get an instance of [`MonoSslStream`](https://github.com/mono/mono/blob/master/mcs/class/Mono.Security/Mono.Security.Interface/MonoSslStream.cs), using the `MonoTlsSettings` object to specify custom certificate validators.

The `MonoSslStream` class has the same API as `SslStream` and acts as a proxy between your application and the actual `SslStream` implementation.  You can simply use `MonoSslStream` wherever you would use `SslStream` otherwise.

There are currently three different backends:

1. [`LegacySslStream`](https://github.com/mono/mono/blob/work-newtls/mcs/class/System/Mono.Net.Security/LegacySslStream.cs) - this is the default and it's simply a copy of `SslStream` with a new name.

2. `Mono.Security.Providers.DotNet` - lives outside `System.dll` to ensure the proxy works when only using public APIs.

3. `Mono.Security.Providers.NewSystemSource` - the Reference Source's version of `SslStream`.  This depends on the `mono-tls` module at runtime.

Mono-Tls Internals
==================

The new TLS code was designed to be consumed by the Reference Source's implementation of `SslStream`, as a replacement
of their P/Invokes into native Windows libraries.  The bridge between these two lives in [`System/ReferenceSources/SSPIWrapper.cs`](https://github.com/mono/mono/blob/master/mcs/class/System/ReferenceSources/SSPIWrapper.cs).

As a fundamental design principle, the `mono-tls` module does not do any kind of networking access or async operations.  Put in simple terms, it expects to be called with some chunk of data and will respond by saying whether it got enough data or whether it needs more input.

In addition to just being a TLS 1.0, 1.1 and 1.2 implementation, it also provides a fairly extensive test suite and allows to
simulate behaviors via the instrumentation framework.

For instance, the [`Mono.Security.NewTls.Interface.HandshakeInstrumentType`](https://github.com/mono/mono-tls/blob/master/Mono.Security.NewTls.Interface/Mono.Security.NewTls/HandshakeInstrumentType.cs) enum lists abnormal behaviors which can be emulated in debug mode.  In addition to this, the test suite can also override [`SignatureProvider`](https://github.com/mono/mono-tls/blob/master/Mono.Security.NewTls.Interface/Mono.Security.NewTls/SignatureProvider.cs) and [`SettingsProvider`](https://github.com/mono/mono-tls/blob/master/Mono.Security.NewTls.Interface/Mono.Security.NewTls/SettingsProvider.cs).

This is used both for testing and research to understand how certain pieces of the TLS stack are supposed to work.

`Mono.Security.NewTls` vs `Mono.Security.NewTls.Interface`
----------------------------------------------------------

There are three main assemblies: `Mono.Security.NewTls`, `Mono.Security.NewTls.Interface` and `Mono.Security.Providers.NewTls`.

`Mono.Security.NewTls` contains the main implementation, but should be considered as an internal API.  It depends on Mono.Security
and uses several APIs which are not available in PCL, so it's a platform-specific .dll.

`Mono.Security.NewTls.Interface` is a PCL containing a public API.  The test suite and user code should only use this public frontend.

`Mono.Security.Providers.NewTls` implements `Mono.Security.Interface.MonoTlsProvider` using `Mono.Security.Providers.NewSystemSource`.  It is platform-specific because its dependencies are.



*** NEEDS CLEANUP BELOW THIS POINT ****

Running the Tests
-----------------

See [web-tests/README.md](https://github.com/xamarin/web-tests/blob/martin-newtls/README.md) for a detailed overview of the test framework.

The platform-specific test implementation is `Mono.Security.NewTls.TestProvider`.  This project currently exists in two versions: [one](https://github.com/mono/mono-tls/tree/master/Mono.Security.NewTls.TestProvider) for the Console and [another one](https://github.com/mono/mono-tls/tree/master/Android/Mono.Security.NewTls.TestProvider).

Due to some strong-name requirements, the actual Android app also needs to be in a [different project](https://github.com/mono/mono-tls/tree/master/Android/Mono.Security.NewTls.Android).

To run the tests on the Console:

1. Build as explained above.
2. Build the [Mac GUI](https://github.com/xamarin/web-tests/tree/martin-newtls/Xamarin.AsyncTests.MacUI).  You may need to set the current Mono runtime to the default one for this.
3. Run as explained in the [web-tests/README.md](https://github.com/xamarin/web-tests/blob/martin-newtls/README.md), using `Mono.Security.NewTls.TestProvider.exe` as custom test implementation.

To run the tests on Android, use the `Mono.Security.NewTls.Android` app.  iOS is not done yet, but will come shortly.




Last changed October 22nd, 2015,
Martin Baulig <martin.baulig@xamarin.com>

