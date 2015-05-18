//
// InstrumentationTestRunner.cs
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
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.TestRunners;
using Mono.Security.NewTls.Instrumentation;

namespace Mono.Security.NewTls.TestFramework
{
	public class InstrumentationTestRunner : ClientAndServerTestRunner
	{
		public InstrumentationTestRunner (IMonoServer server, IMonoClient client)
			: base (server, client)
		{
		}

		public InstrumentationTestRunner (IMonoServer server, IMonoClient client, MonoClientAndServerParameters parameters)
			: base (server, client, parameters)
		{
		}

		public static MonoClientAndServerParameters GetParameters (InstrumentationType type)
		{
			var instrument = new InstrumentCollection ();
			var parameters = new MonoClientAndServerParameters (type.ToString (), ResourceManager.SelfSignedServerCertificate);
			parameters.ClientCertificateValidator = DependencyInjector.Get<ICertificateProvider> ().AcceptAll ();
			parameters.ServerInstrumentation = instrument;

			switch (type) {
			case InstrumentationType.None:
				break;

			case InstrumentationType.DisableRenegotiation:
				instrument.Settings.DisableRenegotiation = true;
				break;

			case InstrumentationType.CloseServerConnection:
				instrument.Install (HandshakeInstrumentType.CloseServerConnection);
				parameters.ServerFlags = ServerFlags.ExpectServerException;
				parameters.ClientFlags = ClientFlags.ExpectWebException;
				break;

			default:
				throw new NotImplementedException ();
			}

			return parameters;
		}
	}
}

