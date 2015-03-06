Mono's New TLS Implementation
=============================

Dependencies:

* xamarin/web-tests from the 'martin-newtls' branch
  (https://github.com/xamarin/web-tests/tree/martin-newtls)
  included as submodule.
  
* mono/mono from the 'work-newtls' branch
  (https://github.com/mono/mono/tree/work-newtls)
  
  This must be installed in /Workspace/INSTALL at the moment.
  
  FIXME: To use a different prefix, need to make sure we find the
  openssl shared libraries at runtime.

* FIXME:
  Temporarily need mono from the old 'work-newtls-master' branch
  until a build problem is fixed.
  
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

