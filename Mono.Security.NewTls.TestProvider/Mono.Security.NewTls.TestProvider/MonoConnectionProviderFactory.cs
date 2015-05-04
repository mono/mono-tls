//
// ConnectionProvider.cs
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
using System.Net;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.TestProvider
{
	using TestFramework;

	class MonoConnectionProviderFactory : IMonoConnectionProviderFactory
	{
		readonly IConnectionProvider dotNetProvider;
		readonly IMonoConnectionProvider monoProvider;
#if HAVE_OPENSSL
		readonly IMonoConnectionProvider openSslProvider;
#endif

		internal MonoConnectionProviderFactory ()
		{
			monoProvider = new MonoProvider ();
#if HAVE_OPENSSL
			openSslProvider = new OpenSslProvider ();
#endif
		}

		public bool IsSupported (ConnectionProviderType type)
		{
			switch (type) {
			case ConnectionProviderType.Mono:
				return true;
#if HAVE_OPENSSL
			case ConnectionProviderType.OpenSsl:
				return true;
#endif
			default:
				return false;
			}
		}

		public bool HasConnectionInfo (ConnectionProviderType type)
		{
			switch (type) {
			case ConnectionProviderType.Mono:
				return true;
#if HAVE_OPENSSL
			case ConnectionProviderType.OpenSsl:
				return true;
#endif
			default:
				return false;
			}
		}

		public bool CanSelectCiphers (ConnectionProviderType type)
		{
			switch (type) {
			case ConnectionProviderType.Mono:
				return true;
#if HAVE_OPENSSL
			case ConnectionProviderType.OpenSsl:
				return true;
#endif
			default:
				return false;
			}
		}

		public IConnectionProvider GetProvider (ConnectionProviderType type)
		{
			if (type == ConnectionProviderType.DotNet)
				return dotNetProvider;
			return GetMonoProvider (type);
		}

		public IMonoConnectionProvider GetMonoProvider (ConnectionProviderType type)
		{
			switch (type) {
			case ConnectionProviderType.Mono:
				return monoProvider;
#if HAVE_OPENSSL
			case ConnectionProviderType.OpenSsl:
				return openSslProvider;
#endif
			default:
				throw new NotSupportedException ();
			}
		}

		abstract class ConnectionProvider : IConnectionProvider
		{
			public abstract IClient CreateClient (ClientParameters parameters);

			public abstract IServer CreateServer (ServerParameters parameters);
		}

		abstract class MonoConnectionProvider : ConnectionProvider, IMonoConnectionProvider
		{
			public override IClient CreateClient (ClientParameters parameters)
			{
				return CreateMonoClient ((MonoClientParameters)parameters);
			}

			public override IServer CreateServer (ServerParameters parameters)
			{
				return CreateMonoServer ((MonoServerParameters)parameters);
			}

			public abstract IMonoClient CreateMonoClient (MonoClientParameters parameters);

			public abstract IMonoServer CreateMonoServer (MonoServerParameters parameters);
		}

		class MonoProvider : MonoConnectionProvider
		{
			public override IMonoClient CreateMonoClient (MonoClientParameters parameters)
			{
				return new MonoClient (GetEndPoint (parameters), parameters);
			}
			public override IMonoServer CreateMonoServer (MonoServerParameters parameters)
			{
				return new MonoServer (GetEndPoint (parameters), parameters);
			}
		}

#if HAVE_OPENSSL
		class OpenSslProvider : MonoConnectionProvider
		{
			public override IMonoClient CreateMonoClient (MonoClientParameters parameters)
			{
				return new OpenSslClient (GetEndPoint (parameters), parameters);
			}
			public override IMonoServer CreateMonoServer (MonoServerParameters parameters)
			{
				return new OpenSslServer (GetEndPoint (parameters), parameters);
			}
		}
#endif

		static IPEndPoint GetEndPoint (ConnectionParameters parameters)
		{
			if (parameters.EndPoint != null)
				return new IPEndPoint (IPAddress.Parse (parameters.EndPoint.Address), parameters.EndPoint.Port);
			else
				return new IPEndPoint (IPAddress.Loopback, 4433);
		}
	}
}

