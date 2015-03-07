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

* For Android and iOS:

  Custom built of Xamarin.Android / Xamarin.iOS with Mono from
  the the 'work-newtls' branch.
  
  You also need to build mcs/class/Mono.Security.Providers and
  install the binaries.

* Download the openssl 1.0.1 sources, configure with

  $ ./config -t
  $ ./Configure darwin-i386-cc --prefix=/Workspace/INSTALL -shared
  $ make
  $ make install
  
  This install a shared-library build of openssl in /Workspace/INSTALL.
  
* Make sure you have Xcode installed.

* Build the native library with

  $ make -f Makefile.native
  
* Build MartinPlayground.mdw.

Reference Source and how the pieces fit together
------------------------------------------------

A slightly outdated documentation is here:
https://github.com/mono/mono/blob/work-newtls/mcs/class/Mono.Security.Providers/README.md

This still needs to be cleaned up.

