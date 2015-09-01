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
using Xamarin.WebTests.TestFramework;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestFramework
{
	using TestFeatures;

	[InstrumentationConnectionProvider (Identifier = "ClientAndServerProvider")]
	public class InstrumentationConnectionProvider : ClientAndServerProvider
	{
		public InstrumentationCategory Category {
			get;
			private set;
		}

		public InstrumentationConnectionFlags Flags {
			get;
			private set;
		}

		static string GetFlagsName (InstrumentationConnectionFlags flags)
		{
			if ((flags & InstrumentationConnectionFlags.ManualClient) != 0)
				return ":ManualClient";
			else if ((flags & InstrumentationConnectionFlags.ManualServer) != 0)
				return ":ManuelServer";
			else
				return string.Empty;
		}

		public InstrumentationConnectionProvider (ConnectionProvider client, ConnectionProvider server, InstrumentationCategory category, InstrumentationConnectionFlags flags)
			: base (client, server, string.Format ("{0}:{1}:{2}{3}", client.Name, server.Name, category, GetFlagsName (flags)))
		{
			Category = category;
			Flags = flags;
		}
	}
}
