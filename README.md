Mono's New TLS Implementation
=============================

Dependencies:
-------------

* Xamarin.AsyncTests from the [martin-newtls](https://github.com/xamarin/web-tests/tree/martin-newtls) branch.  This is included as a submodule.
  
* Mono 4.0 must be installed as system-default Mono in `/Library/Frameworks/Mono.framework`.
  
  This is required because some internals in the binary serialization
  format have changed, which Xamarin Studio uses to communicate to the
  external `mdtool` build process when building against a custom runtime.
  
* Mono from the [work-newtls](https://github.com/mono/mono/tree/work-newtls) branch installed into a custom prefix.
  
  At the moment, this custom prefix must be `/Workspace/INSTALL` - this is unfortunately hardcoded in the [native Xcode project](https://github.com/mono/mono-tls/blob/master/NativeOpenSsl/NativeOpenSsl.xcodeproj/project.pbxproj) at the moment.
  
  FIXME: To use a different prefix, need to make sure we find the
  openssl shared libraries at runtime.
  
  This version of Mono must be selected as current runtime in
  Xamarin Studio (go to Preferences / .NET Runtime to install it,
  then select via Project / Active Runtime ...).

* Shared-library build of OpenSsl 1.0.1.

  The default version of OpenSsl on OS X is too old and it's also not built as shared library.  You need to download the openssl 1.0.1 sources, then configure and compile with:
  
```
    $ ./config -t
    $ ./Configure darwin-i386-cc --prefix=/Workspace/INSTALL -shared
    $ make
    $ make install
```
  
* Xcode

* Build the native library with

```
  $ make -f Makefile.native
```

* Open `MartinsPlayground.sln` in Xamarin Studio and select `/Workspace/INSTALL` as current runtime.


Android and iOS
---------------

For Android and iOS you will need a custom build of Xamarin.Android / Xamarin.iOS with Mono from the
`work-newtls` branch.  You also need to build `mcs/class/Mono.Security.Providers` and install the binaries.

Reference Source and how the pieces fit together
------------------------------------------------

See [mcs/class/Mono.Security.Providers/README.md](
https://github.com/mono/mono/blob/work-newtls/mcs/class/Mono.Security.Providers/README.md) for an overview of the new `Mono.Security.Interface` APIs.

The new TLS code requires Microsoft's `SslStream` implementation from the referencesource, the corresponding files are:

* [System/Net/SecureProtocols/SslStream.cs](https://github.com/mono/referencesource/blob/mono-4.0.0-branch/System/net/System/Net/SecureProtocols/SslStream.cs)
* [System/Net/SecureProtocols/_SslStream.cs](https://github.com/mono/referencesource/blob/mono-4.0.0-branch/System/net/System/Net/SecureProtocols/_SslStream.cs)
* [System/Net/SecureProtocols/_SslState.cs](https://github.com/mono/referencesource/blob/mono-4.0.0-branch/System/net/System/Net/SecureProtocols/_SslState.cs)
* [System/Net/_SecureChannel.cs](https://github.com/mono/referencesource/blob/mono-4.0.0-branch/System/net/System/Net/_SecureChannel.cs)

Main bridge between their code and ours is [mcs/class/System/ReferenceSources/SSPIWrapper.cs](https://github.com/mono/mono/blob/work-newtls/mcs/class/System/ReferenceSources/SSPIWrapper.cs).

All these classes are currently not built into `System.dll`, but into `Mono.Security.Providers.NewSystemSource.dll`.

Main bridge between our code and theirs is [Mono.Security.Providers.NewTls.MonoNewTlsStreamFactory](https://github.com/mono/mono-tls/blob/master/Mono.Security.Providers/NewTls/Mono.Security.Providers.NewTls/MonoNewTlsStreamFactory.cs).

The `Mono.Security.Providers.NewTls` module uses advanced `extern alias` compilation magic to create an instance of their `SslStream` class from the `Mono.Security.Providers.NewSystemSource` module (again, this uses advanced `extern alias` compilation magic).
