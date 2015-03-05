//
// TestRunner.cs
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
using SD = System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Mono.Security.NewTls.Android
{
	using Xamarin.AsyncTests;
	using Xamarin.AsyncTests.Framework;
	using Xamarin.AsyncTests.Remoting;
	using Xamarin.AsyncTests.Portable;
	using TestFramework;
	using TestProvider;
	using Tests;

	public class TestRunner : TestApp, ICryptoProvider, IConnectionProvider, IRandomNumberGenerator
	{
		RandomNumberGenerator rng;
		TestFramework framework;

		public TestLogger Logger {
			get {
				throw new NotImplementedException ();
			}
		}

		public SettingsBag Settings {
			get;
			private set;
		}

		public TestRunner ()
		{
			rng = RandomNumberGenerator.Create ();

			PortableSupportImpl.Initialize ();
			DependencyInjector.Register<ICryptoProvider> (this);
			DependencyInjector.Register<IConnectionProvider> (this);

			Settings = SettingsBag.CreateDefault ();
			var assembly = typeof(NewTlsTestFeatures).Assembly;

			framework = TestFramework.GetLocalFramework (assembly);
		}

		static void Debug (string message, params object[] args)
		{
			SD.Debug.WriteLine (message, args);
		}

		static IPEndPoint GetEndpoint (string text)
		{
			int port;
			string host;
			var pos = text.IndexOf (":");
			if (pos < 0) {
				host = text;
				port = 8888;
			} else {
				host = text.Substring (0, pos);
				port = int.Parse (text.Substring (pos + 1));
			}

			var address = IPAddress.Parse (host);
			return new IPEndPoint (address, port);
		}

		public async Task RunServer ()
		{
			var server = await TestServer.StartServer (this, framework, CancellationToken.None);
			Debug ("SERVER STARTED: {0}", server);
			await server.WaitForExit (CancellationToken.None);
		}

		#region ICryptoProvider implementation

		public IRandomNumberGenerator GetRandomNumberGenerator ()
		{
			return this;
		}

		public byte[] GetRandomBytes (int count)
		{
			var data = new byte [count];
			rng.GetBytes (data);
			return data;
		}

		public bool IsSupported (CryptoProviderType type, bool needsEncryption)
		{
			if (type == CryptoProviderType.Mono)
				return true;
			if (needsEncryption)
				return false;
			if (type == CryptoProviderType.OpenSsl)
				return true;
			return false;
		}

		public IHashTestHost GetHashTestHost (CryptoProviderType type)
		{
			switch (type) {
			case CryptoProviderType.Mono:
				return new MonoCryptoProvider ();
			default:
				throw new NotSupportedException ();
			}
		}

		public IEncryptionTestHost GetEncryptionTestHost (CryptoProviderType type, CryptoTestParameters parameters)
		{
			switch (type) {
			case CryptoProviderType.Mono:
				return new MonoCryptoProvider { Parameters = parameters };
			default:
				throw new NotSupportedException ();
			}
		}

		#endregion

		#region IConnectionProvider implementation

		public bool IsSupported (ConnectionProviderType type)
		{
			if (type == ConnectionProviderType.Mono)
				return true;
			else
				return false;
		}

		public IClient CreateClient (ConnectionProviderType type, IClientParameters parameters)
		{
			if (type == ConnectionProviderType.Mono)
				return new DotNetClient (GetLocalEndPoint (), parameters);
			throw new NotSupportedException ();
		}

		public IServer CreateServer (ConnectionProviderType type, IServerParameters parameters)
		{
			if (type == ConnectionProviderType.Mono)
				return new DotNetServer (GetLocalEndPoint (), parameters);
			else
				throw new NotSupportedException ();
		}

		#endregion

		IPEndPoint GetLocalEndPoint ()
		{
			return new IPEndPoint (IPAddress.Loopback, 4433);
		}
	}
}

