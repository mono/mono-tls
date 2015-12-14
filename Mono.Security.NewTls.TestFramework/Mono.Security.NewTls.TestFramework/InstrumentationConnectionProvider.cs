//
// InstrumentationConnectionProvider.cs
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
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.MonoConnectionFramework;
using Xamarin.WebTests.MonoTestFramework;
using Xamarin.WebTests.TestFramework;

namespace Mono.Security.NewTls.TestFramework
{
	using ConnectionFramework;
	using TestFeatures;

	[InstrumentationConnectionProvider (Identifier = "ClientAndServerProvider")]
	public class InstrumentationConnectionProvider : MonoConnectionTestProvider
	{
		new public InstrumentationCategory Category {
			get { return (InstrumentationCategory)base.Category; }
		}

		new public InstrumentationConnectionFlags Flags {
			get { return (InstrumentationConnectionFlags)base.Flags; }
		}

		public override IClient CreateClient (ConnectionParameters parameters)
		{
			var provider = (MonoConnectionProvider)Client;
			var instrumentationExtension = new InstrumentationConnectionExtension (provider, parameters);
			return provider.CreateMonoClient (parameters, instrumentationExtension);
		}

		public override IServer CreateServer (ConnectionParameters parameters)
		{
			var provider = (MonoConnectionProvider)Server;
			var instrumentationExtension = new InstrumentationConnectionExtension (provider, parameters);
			return provider.CreateMonoServer (parameters, instrumentationExtension);
		}

		static string GetFlagsName (InstrumentationConnectionFlags flags)
		{
			if ((flags & InstrumentationConnectionFlags.ManualClient) != 0)
				return ":ManualClient";
			else if ((flags & InstrumentationConnectionFlags.ManualServer) != 0)
				return ":ManualServer";
			else
				return string.Empty;
		}

		public InstrumentationConnectionProvider (ConnectionProvider client, ConnectionProvider server, InstrumentationCategory category, InstrumentationConnectionFlags flags)
			: base (client, server, (MonoConnectionTestCategory)category, (MonoConnectionTestFlags)flags)
		{
		}
	}
}
