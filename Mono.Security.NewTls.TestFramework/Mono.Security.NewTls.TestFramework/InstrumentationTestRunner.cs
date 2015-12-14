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
using System.Net;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Mono.Security.Interface;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.MonoConnectionFramework;
using Xamarin.WebTests.MonoTestFramework;
using Xamarin.WebTests.HttpFramework;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.TestRunners;

namespace Mono.Security.NewTls.TestFramework
{
	using ConnectionFramework;

	public abstract class InstrumentationTestRunner : MonoConnectionTestRunner, InstrumentationProvider
	{
		new public InstrumentationParameters Parameters {
			get { return (InstrumentationParameters)base.Parameters; }
		}

		new public InstrumentationCategory Category {
			get { return (InstrumentationCategory)base.Parameters.Category; }
		}

		new public InstrumentationConnectionProvider Provider {
			get { return (InstrumentationConnectionProvider)base.Provider; }
		}

		new public InstrumentationConnectionFlags ConnectionFlags {
			get { return (InstrumentationConnectionFlags)base.ConnectionFlags; }
		}

		public InstrumentationTestRunner (IServer server, IClient client, InstrumentationConnectionProvider provider, InstrumentationParameters parameters)
			: base (server, client, provider, parameters)
		{
			if ((provider.Flags & InstrumentationConnectionFlags.ServerInstrumentation) != 0)
				((MonoConnection)server).InstallInstrumentationProvider (this);
			if ((provider.Flags & InstrumentationConnectionFlags.ClientInstrumentation) != 0)
				((MonoConnection)client).InstallInstrumentationProvider (this);
		}

		public abstract Instrumentation CreateInstrument (TestContext ctx, MonoTlsSettings settings);

		public static InstrumentationConnectionFlags GetConnectionFlags (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.SimpleMonoClient:
			case InstrumentationCategory.SelectClientCipher:
				return InstrumentationConnectionFlags.RequireMonoClient;
			case InstrumentationCategory.SimpleMonoServer:
			case InstrumentationCategory.SelectServerCipher:
				return InstrumentationConnectionFlags.RequireMonoServer;
			case InstrumentationCategory.SimpleMonoConnection:
			case InstrumentationCategory.MonoProtocolVersions:
			case InstrumentationCategory.SelectCipher:
				return InstrumentationConnectionFlags.RequireMonoClient | InstrumentationConnectionFlags.RequireMonoServer;
			case InstrumentationCategory.AllClientSignatureAlgorithms:
			case InstrumentationCategory.ClientSignatureParameters:
			case InstrumentationCategory.ClientConnection:
			case InstrumentationCategory.ClientRenegotiation:
			case InstrumentationCategory.MartinTestClient:
				return InstrumentationConnectionFlags.ClientInstrumentation;
			case InstrumentationCategory.AllServerSignatureAlgorithms:
			case InstrumentationCategory.ServerConnection:
			case InstrumentationCategory.ServerRenegotiation:
			case InstrumentationCategory.MartinTestServer:
				return InstrumentationConnectionFlags.ServerInstrumentation;
			case InstrumentationCategory.ServerSignatureParameters:
				return InstrumentationConnectionFlags.ClientInstrumentation | InstrumentationConnectionFlags.ServerInstrumentation;
			case InstrumentationCategory.SignatureAlgorithms:
			case InstrumentationCategory.Connection:
			case InstrumentationCategory.Renegotiation:
			case InstrumentationCategory.CertificateChecks:
				return InstrumentationConnectionFlags.ClientInstrumentation | InstrumentationConnectionFlags.ServerInstrumentation;
			case InstrumentationCategory.MartinTest:
				return InstrumentationConnectionFlags.RequireMonoClient | InstrumentationConnectionFlags.RequireMonoServer | InstrumentationConnectionFlags.RequireTls12;
			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				return InstrumentationConnectionFlags.None;
			}
		}
	}
}

