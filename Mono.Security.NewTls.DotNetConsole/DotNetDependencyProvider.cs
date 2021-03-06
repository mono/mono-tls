﻿//
// DotNetDependencyProvider.cs
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
using System.Threading;
using Xamarin.AsyncTests;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.HttpClient;
using Xamarin.WebTests.Server;

using Xamarin.AsyncTests.Console;

[assembly: DependencyProvider (typeof(Mono.Security.NewTls.DotNetConsole.DotNetDependencyProvider))]

[assembly: AsyncTestSuite (typeof(Mono.Security.NewTls.Tests.NewTlsTestFeatures), true)]

namespace Mono.Security.NewTls.DotNetConsole
{
	using TestFramework;
	using Tests;

	public class DotNetDependencyProvider : IDependencyProvider
	{
		public void Initialize ()
		{
			DependencyInjector.RegisterDependency<IPortableWebSupport> (() => new PortableWebSupportImpl ());
			DependencyInjector.RegisterDependency<ICertificateProvider> (() => new CertificateProvider ());
			DependencyInjector.RegisterDependency<ICryptoProvider> (() => new DotNetCryptoProvider ());

			DependencyInjector.RegisterDependency<IHttpClientProvider> (() => new HttpClientProvider ());
			DependencyInjector.RegisterDependency<ConnectionProviderFactory> (() => new DefaultConnectionProviderFactory ());
			DependencyInjector.RegisterDependency<IStreamProvider> (() => new StreamProvider ());

			DependencyInjector.RegisterDependency<NewTlsTestFeatures> (() => new NewTlsTestFeatures ());

			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;
		}

		static void Main (string[] args)
		{
			Program.Run (typeof(DotNetDependencyProvider).Assembly, args);
		}
	}
}

