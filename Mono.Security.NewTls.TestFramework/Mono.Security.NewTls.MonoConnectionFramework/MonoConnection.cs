//
// MonoConnection.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2014 Xamarin Inc. (http://www.xamarin.com)
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
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Diagnostics;
using System.Collections.Generic;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Mono.Security.NewTls;
using MSI = Mono.Security.Interface;
using Mono.Security.NewTls.TestFramework;

using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.ConnectionFramework;

namespace Mono.Security.NewTls.MonoConnectionFramework
{
	using TestFramework;

	abstract class MonoConnection : DotNetConnection
	{
		public MonoConnection (MonoConnectionProvider provider, ConnectionParameters parameters)
			: base (provider, parameters)
		{
			this.provider = provider;
		}

		MSI.MonoTlsSettings settings;
		MonoConnectionProvider provider;
		MonoSslStream monoSslStream;
		InstrumentationProvider instrumentationProvider;

		public MonoConnectionProvider ConnectionProvider {
			get { return provider; }
		}

		public override bool SupportsCleanShutdown {
			get { return provider.SupportsMonoExtensions; }
		}

		public bool SupportsConnectionInfo {
			get { return provider.SupportsMonoExtensions; }
		}

		public MSI.MonoTlsConnectionInfo GetConnectionInfo ()
		{
			return monoSslStream.GetConnectionInfo ();
		}

		public bool SupportsInstrumentation {
			get { return provider.SupportsInstrumentation; }
		}

		public InstrumentationProvider InstrumentationProvider {
			get {
				if (!SupportsInstrumentation)
					throw new NotSupportedException ();
				return instrumentationProvider;
			} set {
				if (!SupportsInstrumentation)
					throw new NotSupportedException ();
				instrumentationProvider = value;
			}
		}

		protected abstract Task<MonoSslStream> Start (TestContext ctx, Stream stream, MSI.MonoTlsSettings settings, CancellationToken cancellationToken);

		protected abstract void GetSettings (UserSettings settings);

		protected sealed override async Task<ISslStream> Start (TestContext ctx, Stream stream, CancellationToken cancellationToken)
		{
			UserSettings userSettings = new UserSettings ();
			#if DEBUG
			if (SupportsInstrumentation && InstrumentationProvider != null) {
				var instrumentation = InstrumentationProvider.CreateInstrument (ctx);
				if (instrumentation != null && instrumentation.HasSettingsInstrument)
					userSettings = instrumentation.SettingsInstrument.UserSettings;
				userSettings.Instrumentation = instrumentation;
			}
			#endif

			GetSettings (userSettings);

			if (ConnectionProvider.SupportsMonoExtensions) {
				settings = new MSI.MonoTlsSettings ();
				settings.UserSettings = userSettings;
			}

			monoSslStream = await Start (ctx, stream, settings, cancellationToken);
			return monoSslStream;
		}

		protected override Task<bool> TryCleanShutdown ()
		{
			return monoSslStream.TryCleanShutdown ();
		}

		public override string ToString ()
		{
			return string.Format ("[{0}: Provider={1}]", GetType ().Name, provider.Type);
		}
	}
}

