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

	class ConnectionProviderFactory : IConnectionProviderFactory
	{
		readonly IConnectionProvider dotNetProvider;
		readonly IMonoConnectionProvider monoProvider;
#if HAVE_OPENSSL
		readonly IMonoConnectionProvider openSslProvider;
#endif

		internal ConnectionProviderFactory ()
		{
			dotNetProvider = new DotNetProvider ();
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
			public abstract IClient CreateClient (IClientParameters parameters);

			public abstract IServer CreateServer (IServerParameters parameters);
		}

		abstract class MonoConnectionProvider : ConnectionProvider, IMonoConnectionProvider
		{
			public override IClient CreateClient (IClientParameters parameters)
			{
				return CreateMonoClient ((IMonoClientParameters)parameters);
			}

			public override IServer CreateServer (IServerParameters parameters)
			{
				return CreateMonoServer ((IMonoServerParameters)parameters);
			}

			public abstract IMonoClient CreateMonoClient (IMonoClientParameters parameters);

			public abstract IMonoServer CreateMonoServer (IMonoServerParameters parameters);
		}

		class DotNetProvider : ConnectionProvider
		{
			public override IClient CreateClient (IClientParameters parameters)
			{
				return new DotNetClient (GetEndPoint (parameters), parameters);
			}
			public override IServer CreateServer (IServerParameters parameters)
			{
				return new DotNetServer (GetEndPoint (parameters), parameters);
			}
		}

		class MonoProvider : MonoConnectionProvider
		{
			public override IMonoClient CreateMonoClient (IMonoClientParameters parameters)
			{
				return new MonoClient (GetEndPoint (parameters), parameters);
			}
			public override IMonoServer CreateMonoServer (IMonoServerParameters parameters)
			{
				return new MonoServer (GetEndPoint (parameters), parameters);
			}
		}

#if HAVE_OPENSSL
		class OpenSslProvider : MonoConnectionProvider
		{
			public override IMonoClient CreateMonoClient (IMonoClientParameters parameters)
			{
				return new OpenSslClient (GetEndPoint (parameters), parameters);
			}
			public override IMonoServer CreateMonoServer (IMonoServerParameters parameters)
			{
				return new OpenSslServer (GetEndPoint (parameters), parameters);
			}
		}
#endif

		static IPEndPoint GetEndPoint (ICommonConnectionParameters parameters)
		{
			if (parameters.EndPoint != null)
				return new IPEndPoint (IPAddress.Parse (parameters.EndPoint.Address), parameters.EndPoint.Port);
			else
				return new IPEndPoint (IPAddress.Loopback, 4433);
		}
	}
}

