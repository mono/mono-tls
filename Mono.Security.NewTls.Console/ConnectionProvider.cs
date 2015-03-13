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

namespace Mono.Security.NewTls.Console
{
	using TestFramework;

	public class ConnectionProvider : IConnectionProvider
	{
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

		public IClient CreateClient (ConnectionProviderType type, IClientParameters parameters)
		{
			if (type == ConnectionProviderType.DotNet)
				return new DotNetClient (GetLocalEndPoint (), parameters);
			else if (type == ConnectionProviderType.Mono)
				return new MonoClient (GetLocalEndPoint (), parameters);
#if HAVE_OPENSSL
			else if (type == ConnectionProviderType.OpenSsl)
				return new OpenSslClient (GetLocalEndPoint (), parameters);
#endif
			throw new NotSupportedException ();
		}

		public IServer CreateServer (ConnectionProviderType type, IServerParameters parameters)
		{
			if (type == ConnectionProviderType.DotNet)
				return new DotNetServer (GetLocalEndPoint (), parameters);
			else if (type == ConnectionProviderType.Mono)
				return new MonoServer (GetLocalEndPoint (), parameters);
#if HAVE_OPENSSL
			else if (type == ConnectionProviderType.OpenSsl)
				return new OpenSslServer (GetLocalEndPoint (), parameters);
#endif
			else
				throw new NotSupportedException ();
		}

		IPEndPoint GetLocalEndPoint ()
		{
			return new IPEndPoint (IPAddress.Loopback, 4433);
		}
	}
}

