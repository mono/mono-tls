//
// InstrumentationConnectionFilter.cs
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
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestFramework
{
	public class InstrumentationConnectionFilter : ConnectionProviderFilter
	{
		public InstrumentationCategory Category {
			get;
			private set;
		}

		public InstrumentationConnectionFlags Flags {
			get;
			private set;
		}

		public InstrumentationConnectionFilter (InstrumentationCategory category, InstrumentationConnectionFlags flags)
		{
			Category = category;
			Flags = flags;
		}

		bool HasFlag (InstrumentationConnectionFlags flag)
		{
			return (Flags & flag) != 0;
		}

		static bool SupportsInstrumentation (ConnectionProvider provider)
		{
			var monoProvider = provider as IMonoConnectionProvider;
			return monoProvider != null && monoProvider.SupportsInstrumentation;
		}

		static bool SupportsMonoExtensions (ConnectionProvider provider)
		{
			var monoProvider = provider as IMonoConnectionProvider;
			return monoProvider != null && monoProvider.SupportsMonoExtensions;
		}

		static bool SupportsTls12 (ConnectionProvider provider)
		{
			return (provider.Flags & ConnectionProviderFlags.SupportsTls12) != 0;
		}

		static bool SupportsEcDhe (ConnectionProvider provider)
		{
			return (provider.Flags & ConnectionProviderFlags.SupportsEcDheCiphers) != 0;
		}

		protected override ClientAndServerProvider Create (ConnectionProvider client, ConnectionProvider server)
		{
			return new InstrumentationConnectionProvider (client, server, Category, Flags);
		}

		protected virtual bool IsSupported (ConnectionProvider provider)
		{
			if (HasFlag (InstrumentationConnectionFlags.RequireMonoClient) && !SupportsMonoExtensions (provider))
				return false;
			if (HasFlag (InstrumentationConnectionFlags.RequireEcDhe) && !SupportsEcDhe (provider))
				return false;
			if ((provider.Flags & ConnectionProviderFlags.SupportsTls12) == 0)
				return false;

			return true;
		}

		protected virtual bool IsClientSupported (ConnectionProvider provider)
		{
			if (HasFlag (InstrumentationConnectionFlags.ClientInstrumentation) && !SupportsInstrumentation (provider))
				return false;

			return IsSupported (provider);
		}

		protected virtual bool IsServerSupported (ConnectionProvider provider)
		{
			if (HasFlag (InstrumentationConnectionFlags.ServerInstrumentation) && !SupportsInstrumentation (provider))
				return false;

			return IsSupported (provider);
		}

		public override bool IsClientSupported (TestContext ctx, ConnectionProvider provider, string filter)
		{
			if (HasFlag (InstrumentationConnectionFlags.ManualClient) && provider.Type != ConnectionProviderType.Manual)
				return false;
			if (!IsClientSupported (provider))
				return false;

			var match = MatchesFilter (provider, filter);
			if (match != null)
				return match.Value;
			if ((provider.Flags & ConnectionProviderFlags.IsExplicit) != 0)
				return false;

			return true;
		}

		public override bool IsServerSupported (TestContext ctx, ConnectionProvider provider, string filter)
		{
			if (HasFlag (InstrumentationConnectionFlags.ManualServer) && provider.Type != ConnectionProviderType.Manual)
				return false;
			if (!IsServerSupported (provider))
				return false;

			var match = MatchesFilter (provider, filter);
			if (match != null)
				return match.Value;
			if ((provider.Flags & ConnectionProviderFlags.IsExplicit) != 0)
				return false;

			return true;
		}
	}
}

