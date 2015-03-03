//
// Program.cs
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
using System.IO;
using System.Xml;
using System.Xml.Linq;
using System.Reflection;
using SD = System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using NDesk.Options;
using Xamarin.WebTests.Portable;

namespace Mono.Security.NewTls.Console
{
	using Xamarin.AsyncTests;
	using Xamarin.AsyncTests.Remoting;
	using Xamarin.AsyncTests.Portable;
	using Xamarin.AsyncTests.Framework;
	using Mono.Security.NewTls.TestFramework;
	using Mono.Security.NewTls.TestProvider;
	using Mono.Security.NewTls.Tests;

	public class Program : TestApp, ICryptoProvider
	{
		public string SettingsFile {
			get;
			private set;
		}

		const string XmlOutputFileName = "TestResult.xml";

		public SettingsBag Settings {
			get { return settings; }
		}

		public TestLogger Logger {
			get { return logger; }
		}

		public TestFramework Framework {
			get { return framework; }
		}

		public IPortableSupport PortableSupport {
			get { return support; }
		}

		public int LogLevel {
			get;
			private set;
		}

		public bool Server {
			get;
			private set;
		}

		public bool NoXml {
			get;
			private set;
		}

		TestSession session;
		IPortableSupport support;
		SettingsBag settings;
		TestFramework framework;
		TestLogger logger;

		public static void Main (string[] args)
		{
			SD.Debug.AutoFlush = true;
			SD.Debug.Listeners.Add (new SD.ConsoleTraceListener ());

			var support = PortableSupportImpl.Initialize ();

			var program = new Program (support, args);

			try {
				var task = program.Run ();
				task.Wait ();
			} catch (Exception ex) {
				Debug ("ERROR: {0}", ex);
			}
		}

		Program (IPortableSupport support, string[] args)
		{
			this.support = support;

			DependencyInjector.Register<ICryptoProvider> (this);

			LogLevel = -1;

			var p = new OptionSet ();
			p.Add ("settings=", v => SettingsFile = v);
			p.Add ("server", v => Server = true);
			p.Add ("noxml", v => NoXml = true);
			p.Add ("log-level=", v => LogLevel = int.Parse (v));
			var remaining = p.Parse (args);

			settings = LoadSettings (SettingsFile);

			Assembly assembly;
			if (remaining.Count == 1)
				assembly = Assembly.LoadFile (remaining [0]);
			else if (remaining.Count == 0)
				assembly = typeof(NewTlsTestSuite).Assembly;
			else
				throw new InvalidOperationException ();

			logger = new TestLogger (new ConsoleLogger (this));
			logger.LogLevel = LogLevel;

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

		static SettingsBag LoadSettings (string filename)
		{
			if (filename == null || !File.Exists (filename))
				return SettingsBag.CreateDefault ();

			using (var reader = new StreamReader (filename)) {
				var doc = XDocument.Load (reader);
				return Connection.LoadSettings (doc.Root);
			}
		}

		void SaveSettings ()
		{
			if (SettingsFile == null)
				return;

			using (var writer = new StreamWriter (SettingsFile)) {
				var xws = new XmlWriterSettings ();
				xws.Indent = true;

				using (var xml = XmlTextWriter.Create (writer, xws)) {
					var node = Connection.WriteSettings (Settings);
					node.WriteTo (xml);
					xml.Flush ();
				}
			}
		}

		Task Run ()
		{
			if (Server)
				return RunServer ();
			else
				return RunLocal ();
		}

		async Task RunServer ()
		{
			var server = await TestServer.StartServer (this, Framework, CancellationToken.None);
			Debug ("SERVER STARTED: {0}", server);
			await server.WaitForExit (CancellationToken.None);
		}

		async Task RunLocal ()
		{
			session = TestSession.CreateLocal (this, framework);
			var test = await session.GetRootTestCase (CancellationToken.None);

			Debug ("Got test: {0}", test);
			var result = await session.Run (test, CancellationToken.None);
			Debug ("Got result: {0}", result);

			Debug ("{0} tests, {1} passed, {2} errors, {3} ignored.", countTests, countSuccess, countErrors, countIgnored);

			if (!NoXml) {
				var serialized = TestSerializer.WriteTestResult (result);
				var settings = new XmlWriterSettings ();
				settings.Indent = true;
				using (var writer = XmlTextWriter.Create (XmlOutputFileName, settings))
					serialized.WriteTo (writer);
				Debug ("Result writting to {0}.", XmlOutputFileName);
			}
		}

		void OnLogMessage (string message)
		{
			Debug (message);
		}

		void OnLogDebug (int level, string message)
		{
			if (level > Logger.LogLevel)
				return;
			Debug (message);
		}

		int countTests;
		int countSuccess;
		int countErrors;
		int countIgnored;

		void OnStatisticsEvent (TestLoggerBackend.StatisticsEventArgs args)
		{
			switch (args.Type) {
			case TestLoggerBackend.StatisticsEventType.Running:
				++countTests;
				Debug ("Running {0}", args.Name);
				break;
			case TestLoggerBackend.StatisticsEventType.Finished:
				switch (args.Status) {
				case TestStatus.Success:
					++countSuccess;
					break;
				case TestStatus.Ignored:
				case TestStatus.None:
					++countIgnored;
					break;
				default:
					++countErrors;
					break;
				}

				Debug ("Finished {0}: {1}", args.Name, args.Status);
				break;
			case TestLoggerBackend.StatisticsEventType.Reset:
				break;
			}
		}

		class ConsoleLogger : TestLoggerBackend
		{
			readonly Program Program;

			public ConsoleLogger (Program program)
			{
				Program = program;
			}

			protected override void OnLogEvent (LogEntry entry)
			{
				switch (entry.Kind) {
				case EntryKind.Debug:
					Program.OnLogDebug (entry.LogLevel, entry.Text);
					break;

				case EntryKind.Error:
					if (entry.Error != null)
						Program.OnLogMessage (string.Format ("ERROR: {0}", entry.Error));
					else
						Program.OnLogMessage (entry.Text);
					break;

				default:
					Program.OnLogMessage (entry.Text);
					break;
				}
			}

			protected override void OnStatisticsEvent (StatisticsEventArgs args)
			{
				Program.OnStatisticsEvent (args);
			}
		}

		#region ICryptoProvider implementation

		public bool IsSupported (CryptoProviderType type)
		{
			if (type == CryptoProviderType.Mono)
				return true;
			return false;
		}

		public ICryptoTestProvider GetProvider (CryptoProviderType type)
		{
			switch (type) {
			case CryptoProviderType.Mono:
				return new MonoCryptoProvider ();

			default:
				throw new NotSupportedException ();
			}
		}

		#endregion
	}
}

