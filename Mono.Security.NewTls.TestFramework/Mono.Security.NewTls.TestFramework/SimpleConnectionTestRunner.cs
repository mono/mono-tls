//
// SimpleConnectionTestRunner.cs
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
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.TestRunners;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Providers;

namespace Mono.Security.NewTls.TestFramework
{
	public class SimpleConnectionTestRunner : InstrumentationTestRunner
	{
		new public SimpleConnectionParameters Parameters {
			get { return (SimpleConnectionParameters)base.Parameters; }
		}

		public SimpleConnectionType Type {
			get { return Parameters.Type; }
		}

		public SimpleConnectionTestRunner (IServer server, IClient client, SimpleConnectionParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
		}

		public override Instrumentation CreateInstrument (TestContext ctx)
		{
			return null;
		}

		public static IEnumerable<SimpleConnectionParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.SimpleClient:
				return ClientConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.SimpleServer:
				return ServerConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.SimpleConnection:
				return ConnectionTypes.Select (t => Create (ctx, category, t));

			case InstrumentationCategory.MartinTest:
				return MartinTestTypes.Select (t => Create (ctx, category, t));

			default:
				ctx.AssertFail ("Unsupported connection category: '{0}'.", category);
				return null;
			}
		}

		internal static readonly SimpleConnectionType[] ClientConnectionTypes = {
			SimpleConnectionType.MartinTest
		};

		internal static readonly SimpleConnectionType[] ServerConnectionTypes = {
			SimpleConnectionType.MartinTest
		};

		internal static readonly SimpleConnectionType[] ConnectionTypes = {
			SimpleConnectionType.MartinTest
		};

		internal static readonly SimpleConnectionType[] MartinTestTypes = {
			SimpleConnectionType.MartinTest
		};

		static SimpleConnectionParameters CreateParameters (InstrumentationCategory category, SimpleConnectionType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new SimpleConnectionParameters (category, type, name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ProtocolVersion = ProtocolVersions.Tls12
			};
		}

		static SimpleConnectionParameters Create (TestContext ctx, InstrumentationCategory category, SimpleConnectionType type)
		{
			var parameters = CreateParameters (category, type);

			switch (type) {
			case SimpleConnectionType.MartinTest:
				break;

			default:
				ctx.AssertFail ("Unsupported connection type: '{0}'.", type);
				break;
			}

			return parameters;
		}
	}
}

