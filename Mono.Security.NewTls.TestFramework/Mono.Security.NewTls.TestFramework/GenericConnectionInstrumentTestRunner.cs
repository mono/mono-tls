//
// GenericConnectionInstrumentTestRunner.cs
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
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Resources;

namespace Mono.Security.NewTls.TestFramework
{
	public class GenericConnectionInstrumentTestRunner : ConnectionInstrumentTestRunner
	{
		public GenericConnectionInstrumentTestRunner (IServer server, IClient client, GenericConnectionInstrumentParameters parameters, MonoConnectionFlags flags)
			: base (server, client, parameters, flags)
		{
		}

		protected override InstrumentationConnectionHandler CreateConnectionHandler ()
		{
			return new ConnectionInstrumentConnectionHandler (this);
		}

		public static bool IsSupported (GenericConnectionInstrumentParameters parameters, ConnectionProviderType clientType, ConnectionProviderType serverType)
		{
			return true;
		}

		public static IEnumerable<GenericConnectionInstrumentParameters> GetParameters (TestContext ctx, InstrumentationCategory category)
		{
			return GetInstrumentationTypes (ctx, category).Select (t => Create (ctx, category, t));
		}

		public static IEnumerable<GenericConnectionInstrumentType> GetInstrumentationTypes (TestContext ctx, InstrumentationCategory category)
		{
			switch (category) {
			case InstrumentationCategory.ClientConnection:
				yield return GenericConnectionInstrumentType.FragmentHandshakeMessages;
				yield return GenericConnectionInstrumentType.SendBlobAfterReceivingFinish;
				break;

			case InstrumentationCategory.ServerConnection:
				yield return GenericConnectionInstrumentType.FragmentHandshakeMessages;
				yield return GenericConnectionInstrumentType.UnsupportedServerCertificate;
				break;

			case InstrumentationCategory.Connection:
				yield return GenericConnectionInstrumentType.FragmentHandshakeMessages;
				yield return GenericConnectionInstrumentType.ServerProvidesUnsupportedCertificate;
				break;

			case InstrumentationCategory.ManualClient:
				yield return GenericConnectionInstrumentType.MartinClientPuppy;
				break;

			case InstrumentationCategory.ManualServer:
				yield return GenericConnectionInstrumentType.MartinServerPuppy;
				break;

			case InstrumentationCategory.MartinTest:
				yield return GenericConnectionInstrumentType.MartinTest;
				break;

			default:
				ctx.AssertFail ("Unsupported instrumentation category: '{0}'.", category);
				break;
			}
		}

		static GenericConnectionInstrumentParameters CreateParameters (InstrumentationCategory category, GenericConnectionInstrumentType type, params object[] args)
		{
			var sb = new StringBuilder ();
			sb.Append (type);
			foreach (var arg in args) {
				sb.AppendFormat (":{0}", arg);
			}
			var name = sb.ToString ();

			return new GenericConnectionInstrumentParameters (category, type, name, ResourceManager.SelfSignedServerCertificate) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ProtocolVersion = ProtocolVersions.Tls12
			};
		}

		static GenericConnectionInstrumentParameters Create (TestContext ctx, InstrumentationCategory category, GenericConnectionInstrumentType type)
		{
			var parameters = CreateParameters (category, type);

			switch (type) {
			case GenericConnectionInstrumentType.FragmentHandshakeMessages:
				parameters.Add (HandshakeInstrumentType.FragmentHandshakeMessages);
				break;

			case GenericConnectionInstrumentType.SendBlobAfterReceivingFinish:
				parameters.Add (HandshakeInstrumentType.SendBlobAfterReceivingFinish);
				break;

			case GenericConnectionInstrumentType.UnsupportedServerCertificate:
				parameters.ServerParameters.ServerCertificate = ResourceManager.DefaultServerCertificate;
				parameters.ExpectServerAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.ServerProvidesUnsupportedCertificate:
				parameters.ServerParameters.ServerCertificate = ResourceManager.DefaultServerCertificate;
				parameters.Add (HandshakeInstrumentType.OverrideServerCertificateSelection);
				parameters.ExpectClientAlert = AlertDescription.UnsupportedCertificate;
				break;

			case GenericConnectionInstrumentType.MartinTest:
				goto case GenericConnectionInstrumentType.ServerProvidesUnsupportedCertificate;

			default:
				ctx.AssertFail ("Unsupported connection instrument: '{0}'.", type);
				break;
			}

			if (parameters.ExpectClientAlert != null || parameters.ExpectServerAlert != null)
				parameters.Add (HandshakeInstrumentType.DontSendAlerts);

			return parameters;
		}
	}
}

