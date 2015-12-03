//
// NewTlsTestSuite.cs
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
using System.Threading;
using System.Collections.Generic;
using Mono.Security.NewTls.TestFramework;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Portable;
using Xamarin.WebTests.Portable;
using Xamarin.WebTests.HttpFramework;
using Xamarin.WebTests.ConnectionFramework;
using Xamarin.WebTests.TestFramework;
using Xamarin.WebTests.Providers;
using Xamarin.WebTests.Resources;

[assembly: AsyncTestSuite (typeof (Mono.Security.NewTls.Tests.NewTlsTestFeatures))]
[assembly: DependencyProvider (typeof (Mono.Security.NewTls.Tests.NewTlsTestFeaturesProvider))]
[assembly: RequireDependency (typeof (ConnectionProviderFactory))]
[assembly: RequireDependency (typeof (ICryptoProvider))]
[assembly: RequireDependency (typeof (ICertificateProvider))]
[assembly: RequireDependency (typeof (IPortableSupport))]

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;
	using TestFeatures;

	public class CryptoTestsAttribute : TestFeatureAttribute
	{
		public override TestFeature Feature {
			get { return NewTlsTestFeatures.Instance.CryptoTests; }
		}
	}

	public class NewTlsTestFeaturesProvider : IDependencyProvider
	{
		public void Initialize ()
		{
			DependencyInjector.RegisterDependency<NewTlsTestFeatures> (() => new NewTlsTestFeatures ());
		}
	}

	public class NewTlsTestFeatures : SharedWebTestFeatures, ISingletonInstance
	{
		public static NewTlsTestFeatures Instance {
			get { return DependencyInjector.Get<NewTlsTestFeatures> (); }
		}

		public readonly TestFeature CryptoTests = new TestFeature ("CryptoTests", "Enable crypto tests", () => SupportsCryptoTests);

		public readonly TestFeature Hello = new TestFeature ("Hello", "Hello World");

		public readonly TestFeature DotNetCryptoProvider = CreateCryptoFeature (
			"DotNetCryptoProvider", "Use .NET as crypto provider", CryptoProviderType.DotNet, false);
		public readonly TestFeature MonoCryptoProvider = CreateCryptoFeature (
			"MonoCryptoProvider", "Use Mono.Security as crypto provider", CryptoProviderType.Mono, false);
		public readonly TestFeature OpenSslCryptoProvider = CreateCryptoFeature (
			"OpenSslCryptoProvider", "Use OpenSSL as crypto provider", CryptoProviderType.OpenSsl, false);

		static bool SupportsCryptoTests {
			get {
				var provider = DependencyInjector.Get<ICryptoProvider> ();
				return provider.IsSupported (CryptoProviderType.DotNet, true);
			}
		}

		static TestFeature CreateCryptoFeature (string name, string description, CryptoProviderType type, bool needsEncryption, bool defaultValue = true)
		{
			var provider = DependencyInjector.Get<ICryptoProvider> ();
			if (!provider.IsSupported (type, needsEncryption)) {
				// read-only and disabled
				return new TestFeature (name, description, () => false);
			}

			return new TestFeature (name, description, defaultValue);
		}

		public readonly TestFeature HttpsWithOldTLS = new TestFeature ("HttpsWithOldTLS", "Use Mono's existing web stack with the old TLS", false);
		public readonly TestFeature HttpsWithNewTLS = new TestFeature ("HttpsWithNewTLS", "Use Mono's existing web stack with the new TLS", true);

		public override string Name {
			get { return "Mono.Security.NewTls.Tests"; }
		}

		protected override bool HasMonoVersion (Version version)
		{
			return true;
		}

		public override IEnumerable<TestFeature> Features {
			get {
				foreach (var feature in base.Features)
					yield return feature;

				yield return Hello;
				yield return DotNetCryptoProvider;
				yield return MonoCryptoProvider;
				yield return OpenSslCryptoProvider;
				yield return HttpsWithOldTLS;
				yield return HttpsWithNewTLS;
				yield return CryptoTests;

				foreach (var feature in InstrumentationTestFeatures.ConnectionFeatures)
					yield return feature;
			}
		}

		public override IEnumerable<TestCategory> Categories {
			get {
				foreach (var category in base.Categories)
					yield return category;

				yield return RenegotiationAttribute.Instance;
			}
		}

		[AttributeUsage (AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = false)]
		public class SelectCryptoProvider : TestParameterAttribute, ITestParameterSource<CryptoProviderType>
		{
			public SelectCryptoProvider (string filter = null, TestFlags flags = TestFlags.ContinueOnError)
				: base (filter, flags)
			{
			}

			public IEnumerable<CryptoProviderType> GetParameters (TestContext ctx, string filter)
			{
				if (filter != null) {
					if (filter.Equals ("dotnet"))
						yield return CryptoProviderType.DotNet;
					else if (filter.Equals ("mono"))
						yield return CryptoProviderType.Mono;
					else if (filter.Equals ("openssl"))
						yield return CryptoProviderType.OpenSsl;
					yield break;
				}

				if (ctx.IsEnabled (Instance.DotNetCryptoProvider))
					yield return CryptoProviderType.DotNet;
				if (ctx.IsEnabled (Instance.MonoCryptoProvider))
					yield return CryptoProviderType.Mono;
				if (ctx.IsEnabled (Instance.OpenSslCryptoProvider))
					yield return CryptoProviderType.OpenSsl;
			}
		}

		[AttributeUsage (AttributeTargets.Parameter | AttributeTargets.Property, AllowMultiple = false)]
		public class SelectServerCertificateAttribute : TestParameterAttribute, ITestParameterSource<ServerCertificateType>
		{
			public SelectServerCertificateAttribute (string filter = null, TestFlags flags = TestFlags.Browsable)
				: base (filter, flags)
			{
			}

			public IEnumerable<ServerCertificateType> GetParameters (TestContext ctx, string filter)
			{
				yield return ServerCertificateType.LocalCA;
				yield return ServerCertificateType.SelfSigned;
			}
		}
	}
}

