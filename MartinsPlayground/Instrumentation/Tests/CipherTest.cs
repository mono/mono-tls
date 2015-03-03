using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Collections.Generic;
using System.Security.Cryptography;
using Mono.Security.NewTls;
using Mono.Security.NewTls.Cipher;
using Mono.Security.NewTls.TestFramework;
using NUnit.Framework;

namespace Mono.Security.Instrumentation.Tests
{
	using Framework;

	[Explicit]
	[ParameterizedTestFixture (typeof (ICryptoTestProvider))]
	public abstract class CipherTest
	{
		public TestConfiguration Configuration {
			get;
			private set;
		}

		public ICryptoTestProvider Provider {
			get;
			private set;
		}

		public ICryptoTestContext Context {
			get;
			private set;
		}

		[TestFixtureSetUp]
		public virtual void SetUp ()
		{
			if (!Provider.SupportsEncryption)
				throw new IgnoreException ("Cipher test provider does not support encryption.");
			Context = Provider.CreateContext ();
			Initialize ();
		}

		protected abstract void Initialize ();

		[TestFixtureTearDown]
		public void TearDown ()
		{
			if (Context != null) {
				Context.Dispose ();
				Context = null;
			}
		}

		public CipherTest (TestConfiguration config, ICryptoTestProvider provider)
		{
			Configuration = config;
			Provider = provider;
		}

		#region Auto-generated

		protected class OutputGenerator {
			TextWriter output;
			string indent;
			RandomNumberGenerator rng;
			Dictionary<string,byte[]> fields;

			public OutputGenerator (TextWriter output, string indent)
			{
				this.output = output;
				this.indent = indent;

				rng = RandomNumberGenerator.Create ();
				fields = new Dictionary<string, byte[]> ();
			}

			public byte[] GetField (string name)
			{
				return fields [name];
			}

			public void WriteRandom (string name, int size)
			{
				var buffer = new byte [size];
				rng.GetBytes (buffer);
				WriteOutput (name, buffer);
			}

			public void WriteOutput (string name, IBufferOffsetSize buffer)
			{
				var array = new byte [buffer.Size];
				Buffer.BlockCopy (buffer.Buffer, buffer.Offset, array, 0, buffer.Size);
				WriteOutput (name, array);
			}

			public void WriteOutput (string name, byte[] buffer)
			{
				fields.Add (name, buffer);
				output.WriteLine (DebugHelper.GenerateCSharp (name, indent, buffer));
			}
		}

		OutputGenerator generator;

		protected OutputGenerator Generator {
			get { return generator; }
		}

		protected byte[] GetField (string name)
		{
			if (generator != null)
				return generator.GetField (name);
			var field = GetType ().GetField (name, BindingFlags.Static | BindingFlags.NonPublic);
			return (byte[])field.GetValue (this);
		}

		protected IBufferOffsetSize GetBuffer (string name)
		{
			return new BufferOffsetSize (GetField (name));
		}

		protected IBufferOffsetSize GetBuffer (string name, int offset, int size)
		{
			var buffer = GetField (name);
			if (offset + size > buffer.Length)
				throw new OverflowException ();
			return new BufferOffsetSize (buffer, offset, size);
		}

		protected void WriteOutput (string name, IBufferOffsetSize buffer)
		{
			if (generator != null) {
				generator.WriteOutput (name, buffer);
				return;
			}

			CheckOutput (name, buffer);
		}

		protected void CheckOutput (string name, IBufferOffsetSize buffer)
		{
			var array = new byte [buffer.Size];
			Buffer.BlockCopy (buffer.Buffer, buffer.Offset, array, 0, buffer.Size);
			var data = GetField (name);
			Assert.That (array, Is.EqualTo (data), "output");
		}

		protected abstract void Generate ();

		// Call this function to randomly generate these byte arrays.
		public void Generate (TextWriter output)
		{
			output.WriteLine ("namespace Mono.Security.Instrumentation.Tests");
			output.WriteLine ("{");
			output.WriteLine ("\tpartial class {0}", GetType ().Name);
			output.WriteLine ("\t{");

			generator = new OutputGenerator (output, "\t\t");

			Generate ();

			output.WriteLine ("\t}");
			output.WriteLine ("}");
		}

		#endregion

	}
}
