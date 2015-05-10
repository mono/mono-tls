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

	public sealed class OpenSslConnectionProvider : MonoConnectionProvider
	{
		public OpenSslConnectionProvider (MonoConnectionProviderFactory factory)
			: base (factory, ConnectionProviderType.OpenSsl, ConnectionProviderFlags.CanSelectCiphers | ConnectionProviderFlags.SupportsMonoExtensions)
		{
		}

		public override ProtocolVersions SupportedProtocols {
			get { return ProtocolVersions.Tls10 | ProtocolVersions.Tls11 | ProtocolVersions.Tls12; }
		}

		public override bool IsCompatibleWith (ConnectionProviderType type)
		{
			return true;
		}

		public override IMonoClient CreateMonoClient (ClientParameters parameters)
		{
			return new OpenSslClient (this, parameters);
		}

		public override IMonoServer CreateMonoServer (ServerParameters parameters)
		{
			return new OpenSslServer (this, parameters);
		}

		public override IClient CreateClient (ClientParameters parameters)
		{
			return CreateMonoClient (parameters);
		}

		public override IServer CreateServer (ServerParameters parameters)
		{
			return CreateMonoServer (parameters);
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

