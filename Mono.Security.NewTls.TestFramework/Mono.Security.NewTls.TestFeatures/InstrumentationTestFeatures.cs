//
// InstrumentationTestFeatures.cs
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
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestFeatures
{
	public static class InstrumentationTestFeatures
	{
		static readonly TestFeature openSslClientFeature = new TestFeature ("OpenSslClient", "Use OpenSsl client", true);
		static readonly TestFeature openSslServerFeature = new TestFeature ("OpenSslServer", "Use OpenSsl server", true);
		static readonly TestFeature dotNetClientFeature = new TestFeature ("DotNetClient", "Use DotNet client", true);
		static readonly TestFeature dotNetServerFeature = new TestFeature ("DotNetServer", "Use DotNet server", true);
		static readonly TestFeature monoClientFeature = new TestFeature ("MonoClient", "Use Mono client", true);
		static readonly TestFeature monoServerFeature = new TestFeature ("MonoServer", "Use Mono server", true);

		public static TestFeature[] ConnectionFeatures = {
			openSslClientFeature, openSslServerFeature, dotNetClientFeature, dotNetServerFeature, monoClientFeature, monoServerFeature
		};

		public static bool IsClientEnabled (TestContext ctx, ConnectionProviderType type)
		{
			return IsEnabled (ctx, type, false);
		}

		public static bool IsServerEnabled (TestContext ctx, ConnectionProviderType type)
		{
			return IsEnabled (ctx, type, true);
		}

		static bool IsEnabled (TestContext ctx, ConnectionProviderType type, bool server)
		{
			var feature = GetConnectionFeature (type, server);
			return feature != null ? ctx.IsEnabled (feature) : false;
		}

		static TestFeature GetConnectionFeature (ConnectionProviderType type, bool server)
		{
			switch (type) {
			case ConnectionProviderType.OpenSsl:
				return server ? openSslServerFeature : openSslClientFeature;
			case ConnectionProviderType.NewTLS:
				return server ? dotNetServerFeature : dotNetClientFeature;
			case ConnectionProviderType.MonoWithNewTLS:
				return server ? monoServerFeature : monoClientFeature;
			default:
				return null;
			}
		}
	}
}

