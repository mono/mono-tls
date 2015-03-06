Mono's New TLS Implementation
=============================

Dependencies:
-------------

* xamarin/web-tests from the 'martin-newtls' branch
  (https://github.com/xamarin/web-tests/tree/martin-newtls)
  included as submodule.
  
* Mono 4.0 must be installed in the system and set as the default Mono
  (/Library/Frameworks/Mono.framework/Versions/4.0.0).
  
  This is required because some internals in the binary serialization
  format have changed, which Xamarin Studio uses to communicate to the
  external 'mdtool' build process when building against a custom runtime.
  
* mono/mono from the 'work-newtls' branch
  (https://github.com/mono/mono/tree/work-newtls)
  
  This must be installed in /Workspace/INSTALL at the moment.
  
  FIXME: To use a different prefix, need to make sure we find the
  openssl shared libraries at runtime.
  
  This version of Mono must be selected as current runtime in
  Xamarin Studio (go to Preferences / .NET Runtime to install it,
  then select via Project / Active Runtime ...).

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

