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
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.HttpFramework;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Resources;
using Xamarin.WebTests.TestRunners;
using Mono.Security.NewTls.Instrumentation;

namespace Mono.Security.NewTls.TestFramework
{
	public class InstrumentationTestRunner : ClientAndServerTestRunner
	{
		new public InstrumentationParameters Parameters {
			get { return (InstrumentationParameters)base.Parameters; }
		}

		public InstrumentationFlags InstrumentationFlags {
			get;
			private set;
		}

		public InstrumentationTestRunner (IServer server, IClient client, InstrumentationParameters parameters, InstrumentationFlags flags)
			: base (server, client, parameters)
		{
			InstrumentationFlags = flags;
		}

		public static IEnumerable<InstrumentationParameters> GetParameters (TestContext ctx, InstrumentationTestCategory category, string filter)
		{
			if (filter != null)
				throw new NotImplementedException ();

			switch (category) {
			case InstrumentationTestCategory.Renegotiation:
				return CreateRenegotiation ();

			case InstrumentationTestCategory.ClientSignatureAlgorithms:
				return CreateSignatureAlgoritms (InstrumentationType.ClientSignatureAlgorithm);

			case InstrumentationTestCategory.SimpleClient:
				return CreateSimpleClient ();

			default:
				throw new NotSupportedException ();
			}
		}

		static ICertificateValidator AcceptAnyCertificate {
			get { return DependencyInjector.Get<ICertificateProvider> ().AcceptAll (); }
		}

		static IEnumerable<InstrumentationParameters> CreateRenegotiation ()
		{
			yield break;
		}

		static IEnumerable<InstrumentationType> GetClientAndServerTypes ()
		{
			yield return InstrumentationType.CloseServerConnection;
			yield return InstrumentationType.DisableRenegotiation;
		}

		static IEnumerable<SignatureAndHashAlgorithm> GetSignatureAlgorithms ()
		{
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Md5, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha1, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha224, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha256, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha384, SignatureAlgorithmType.Rsa);
			yield return new SignatureAndHashAlgorithm (HashAlgorithmType.Sha512, SignatureAlgorithmType.Rsa);
		}

		static IEnumerable<InstrumentationParameters> CreateSignatureAlgoritms (InstrumentationType type)
		{
			return GetSignatureAlgorithms ().Select (algorithm => CreateWithSignatureAlgorithm (type, algorithm));
		}

		static IEnumerable<InstrumentationParameters> CreateSimpleClient ()
		{
			yield return CreateClient (InstrumentationType.None);
		}

		static InstrumentationParameters CreateWithSignatureAlgorithm (InstrumentationType type, SignatureAndHashAlgorithm algorithm)
		{
			var instrument = new InstrumentCollection ();
			instrument.Settings.ClientSignatureParameters.Add (algorithm);

			var name = string.Format ("{0}:{1}:{2}", type, algorithm.Hash, algorithm.Signature);

			return new InstrumentationParameters (name, ResourceManager.SelfSignedServerCertificate, type) {
				ClientCertificateValidator = AcceptAnyCertificate, ServerCertificateValidator = AcceptAnyCertificate,
				ProtocolVersion = ProtocolVersions.Tls12, ClientInstrumentation = instrument
			};
		}

		static InstrumentationParameters CreateClientAndServer (InstrumentationType type)
		{
			var instrument = new InstrumentCollection ();
			var parameters = new InstrumentationParameters (type.ToString (), ResourceManager.SelfSignedServerCertificate, type);
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
				throw new NotSupportedException ();
			}

			return parameters;
		}

		static InstrumentationParameters CreateClient (InstrumentationType type)
		{
			var instrument = new InstrumentCollection ();
			var parameters = new InstrumentationParameters (type.ToString (), ResourceManager.SelfSignedServerCertificate, type);
			parameters.ClientCertificateValidator = DependencyInjector.Get<ICertificateProvider> ().AcceptAll ();
			parameters.ServerInstrumentation = instrument;

			switch (type) {
			case InstrumentationType.None:
				break;

			default:
				throw new NotSupportedException ();
			}

			return parameters;
		}

		protected override Task MainLoop (TestContext ctx, CancellationToken cancellationToken)
		{
			if ((InstrumentationFlags & InstrumentationFlags.ManualServer) != 0)
				return RunWithManualServer (ctx, cancellationToken);

			return base.MainLoop (ctx, cancellationToken);
		}

		async Task RunWithManualServer (TestContext ctx, CancellationToken cancellationToken)
		{
			var clientStream = new StreamWrapper (Client.Stream);

			ctx.LogMessage ("WRITING REQUEST: {0}", Parameters.ClientParameters.TargetHost ?? "<null>");

			await clientStream.WriteLineAsync ("GET / HTTP/1.0");
			try {
				if (Parameters.ClientParameters.TargetHost != null)
					await clientStream.WriteLineAsync (string.Format ("Host: {0}", Parameters.ClientParameters.TargetHost));
				await clientStream.WriteLineAsync ();
			} catch (Exception ex) {
				ctx.LogMessage ("RECEIVED EXCEPTION WHILE WRITING REQUEST: {0}", ex.Message);
			}

			var line = await clientStream.ReadLineAsync ();
			ctx.LogMessage ("GOT RESPONSE: {0}", line);

			HttpProtocol protocol;
			HttpStatusCode status;
			if (!HttpResponse.ParseResponseHeader (line, out protocol, out status))
				throw new ConnectionException ("Got unexpected output from server: '{0}'", line);

			ctx.LogMessage ("GOT RESPONSE: {0} {1}", protocol, status);

			await Shutdown (ctx, SupportsCleanShutdown, true, cancellationToken);
		}
	}
}

