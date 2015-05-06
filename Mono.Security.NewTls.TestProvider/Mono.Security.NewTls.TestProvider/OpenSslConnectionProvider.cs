//
// OpenSslConnectionProvider.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
using System;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class OpenSslConnectionProvider : ConnectionProvider, IMonoConnectionProvider
	{
		public OpenSslConnectionProvider (MonoConnectionProviderFactory factory)
			: base (factory, ConnectionProviderFlags.CanSelectCiphers | ConnectionProviderFlags.SupportsMonoExtensions)
		{
		}

		public IMonoClient CreateMonoClient (MonoClientParameters parameters)
		{
			return new OpenSslClient (parameters);
		}

		public IMonoServer CreateMonoServer (MonoServerParameters parameters)
		{
			return new OpenSslServer (parameters);
		}

		public bool SupportsMonoExtensions {
			get { return true; }
		}

		public override IClient CreateClient (ClientParameters parameters)
		{
			return new OpenSslClient (parameters);
		}

		public override IServer CreateServer (ServerParameters parameters)
		{
			return new OpenSslServer (parameters);
		}

		protected override ISslStreamProvider GetSslStreamProvider ()
		{
			throw new InvalidOperationException ();
		}

		protected override IHttpProvider GetHttpProvider ()
		{
			throw new InvalidOperationException ();
		}
	}
}

