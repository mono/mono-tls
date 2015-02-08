using System;
using System.Reflection;
using System.Collections.Generic;
using NUnit.Core;
using NUnit.Core.Builders;
using NUnit.Core.Extensibility;
using NUnit.Framework;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;

	[NUnitAddin]
	public class AddIn : IAddin, ISuiteBuilder
	{
		public readonly TestConfiguration Configuration = TestConfiguration.DangerousGetInstance ();

		public bool Install (IExtensionHost host)
		{
			var extensionPoint = host.GetExtensionPoint ("SuiteBuilders");
			extensionPoint.Install (this);
			return true;
		}

		public bool CanBuildFrom (Type type)
		{
			if (type.IsAbstract)
				return false;
			return Reflect.HasAttribute (type, typeof(ParameterizedTestFixtureAttribute).FullName, true);
		}

		public Test BuildFrom (Type type)
		{
			var suite = new ParameterizedFixtureSuite (type);
			var attr = (ParameterizedTestFixtureAttribute)Reflect.GetAttribute (type, typeof(ParameterizedTestFixtureAttribute).FullName, true);

			ITestParameterProvider provider;
			if (attr.FactoryName != null)
				provider = Configuration.GetProvider (attr.FactoryName);
			else
				provider = Configuration.GetProvider (attr.Type);

			foreach (var parameter in provider.GetParameters (type)) {
				suite.Add (BuildFixture (type, attr, parameter));
			}

			return suite;
		}

		TestFixture BuildFixture (Type type, ParameterizedTestFixtureAttribute attr, object parameter)
		{
			var categories = (IList<string>)Reflect.GetPropertyValue (attr, "Categories");

			Type fixtureType;
			if (type.IsGenericType)
				fixtureType = type.MakeGenericType (attr.Type);
			else
				fixtureType = type;

			var parameterizedFixture = typeof(ParameterizedTestFixture<>).MakeGenericType (attr.Type);
			var fixture = (NUnitTestFixture)Reflect.Construct (parameterizedFixture, new object[] { fixtureType, Configuration, parameter });

			NUnitFramework.ApplyCommonAttributes (fixtureType, fixture);

			if (categories != null) {
				foreach (string category in categories)
					fixture.Categories.Add (category);
			}

			if (fixture.RunState == RunState.Runnable && attr != null) {
				var objIgnore = Reflect.GetPropertyValue (attr, "Ignore");
				if (objIgnore != null && (bool)objIgnore == true) {
					fixture.RunState = RunState.Ignored;
					fixture.IgnoreReason = (string)Reflect.GetPropertyValue (attr, "IgnoreReason");
				}
			}

			AddTestCases (fixture);
			return fixture;
		}

		void AddTestCases (TestFixture fixture)
		{
			var methods = fixture.FixtureType.GetMethods (
				BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);

			foreach (MethodInfo method in methods) {
				if (!Reflect.HasAttribute (method, typeof(TestAttribute).FullName, true))
					continue;

				var test = BuildTestCase (method, fixture);

				if (test != null)
					fixture.Add (test);
			}
		}

		Test BuildTestCase (MethodInfo method, TestSuite suite)
		{
			var test = NUnitTestCaseBuilder.BuildParameterizedMethodSuite (method, suite);
			if (test.TestCount == 0)
				test = NUnitTestCaseBuilder.BuildSingleTestMethod (method, suite, null);
			test.TestName.FullName = suite.TestName.FullName + "." + test.TestName.Name;
			return test;
		}

	}
}

