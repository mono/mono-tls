//
// InstrumentationConnectionExtension.cs
//
// Author:
//       Martin Baulig <martin.baulig@xamarin.com>
//
// Copyright (c) 2015 Xamarin Inc. (http://www.xamarin.com)
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
using Mono.Security.Interface;
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.MonoConnectionFramework;

namespace Mono.Security.NewTls.ConnectionFramework
{
	using TestFramework;

	class InstrumentationConnectionExtension : IMonoConnectionExtensions
	{
		public ConnectionParameters Parameters {
			get;
			private set;
		}

		public InstrumentationConnectionExtension (MonoConnectionProvider provider, ConnectionParameters parameters)
		{
			Parameters = parameters;
		}

		InstrumentationProvider instrumentationProvider;

		public InstrumentationProvider InstrumentationProvider {
			get { return instrumentationProvider; }
			set { instrumentationProvider = value; }
		}

		public void GetSettings (TestContext ctx, MonoTlsSettings settings)
		{
			#if DEBUG
			if (InstrumentationProvider != null) {
				UserSettings userSettings;
				var instrumentation = InstrumentationProvider.CreateInstrument (ctx, settings);
				if (instrumentation != null && instrumentation.HasSettingsInstrument)
					userSettings = instrumentation.SettingsInstrument.UserSettings;
				else
					userSettings = new UserSettings (settings);
				userSettings.Instrumentation = instrumentation;
			}
			#endif
		}
	}
}

