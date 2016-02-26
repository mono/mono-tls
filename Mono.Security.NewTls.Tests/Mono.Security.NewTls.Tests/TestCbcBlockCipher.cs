using System;
using System.IO;
using System.Text;
using System.Reflection;
using Mono.Security.NewTls;
using Mono.Security.NewTls.TestFramework;
using Xamarin.AsyncTests;
using Xamarin.AsyncTests.Constraints;
using Mono.Security.Interface;

namespace Mono.Security.NewTls.Tests
{
	using TestFramework;

	[AsyncTestFixture]
	public partial class TestCbcBlockCipher : CipherTest
	{
		public override CryptoTestParameters GetParameters ()
		{
			return CryptoTestParameters.CreateCBC (
				TlsProtocolCode.Tls12, CipherSuiteCode.TLS_RSA_WITH_AES_128_CBC_SHA,
				GetField (TestKeyName), GetField (TestMacName), GetField (TestIvName));
		}

		const int MAX_FRAGMENT_SIZE = 16384;

		#region Auto-generated

		const string TestKeyName = "testKey";
		const string TestMacName = "testMac";
		const string TestIvName = "testIV";
		const string TestDataName = "testData";
		const string HelloWorldName = "helloWorld";
		const string MultiFragmentName = "multiFragment";

		const int MagicDataSize = 13;
		const int MagicData2Size = 21;

		const string MagicDataName = "magicData";
		const string MagicData2Name = "magicData2";

		const string HelloWorldResult = "helloWorldResult";
		const string Data0Result = "testData0Result";
		const string Data11Result = "testData11Result";
		const string Data12Result = "testData12Result";
		const string Data13Result = "testData13Result";
		const string DataResult = "testDataResult";
		const string RecordResult = "recordResult";
		const string MultiFragmentResult = "multiFragmentResult";

		const string ExtraPaddingResult = "testWithExtraPadding";

		protected override void Generate (TestContext ctx, IEncryptionTestHost host)
		{
			Generator.WriteRandom (TestKeyName, 32);
			Generator.WriteRandom (TestMacName, 32);
			Generator.WriteRandom (TestIvName, 16);
			Generator.WriteRandom (TestDataName, 128);
			Generator.WriteRandom (MultiFragmentName, 16384 + 32);

			Generator.WriteRandom (MagicDataName, MagicDataSize);
			Generator.WriteRandom (MagicData2Name, MagicData2Size);

			Generator.WriteOutput (HelloWorldName, Encoding.UTF8.GetBytes ("Hello World!"));

			#if FIXME
			SetUp ();
			#endif

			TestHelloWorld (ctx, host);
			TestData (ctx, host);
			TestData0 (ctx, host);
			TestData11 (ctx, host);
			TestData12 (ctx, host);
			TestData13 (ctx, host);
			TestRecord (ctx, host);
			TestMultiFragment (ctx, host);

			TestEncryptWithExtraPadding (ctx, host);
		}

		#endregion

		[AsyncTest]
		public void Sizes (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			ctx.Assert (host.BlockSize, Is.EqualTo (16), "#1");
			ctx.Assert (host.MinExtraEncryptedBytes, Is.EqualTo (37), "#2");
			ctx.Assert (host.MaxExtraEncryptedBytes, Is.EqualTo (52), "#2");
		}

		[AsyncTest]
		public void TestHelloWorld (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (HelloWorldName);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.GreaterThanOrEqualTo (buffer.Size + host.MinExtraEncryptedBytes), "#2");
			ctx.Assert (output.Size, Is.LessThanOrEqualTo (buffer.Size + host.MaxExtraEncryptedBytes), "#3");
			WriteAndCheckOutput (ctx, HelloWorldResult, output);
		}

		[AsyncTest]
		public void TestData0 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (TestDataName, 0, 0);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (48), "#2");
			WriteAndCheckOutput (ctx, Data0Result, output);
		}

		[AsyncTest]
		public void TestData11 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			// This will use zero padding.
			var buffer = GetBuffer (TestDataName, 0, 11);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (48), "#2");
			WriteAndCheckOutput (ctx, Data11Result, output);
		}

		[AsyncTest]
		public void TestData12 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (TestDataName, 0, 12);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (64), "#2");
			WriteAndCheckOutput (ctx, Data12Result, output);
		}

		[AsyncTest]
		public void TestData13 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (TestDataName, 0, 13);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.EqualTo (64), "#2");
			WriteAndCheckOutput (ctx, Data13Result, output);
		}

		[AsyncTest]
		public void TestData (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (TestDataName);
			var output = host.Encrypt (buffer);
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.GreaterThanOrEqualTo (buffer.Size + host.MinExtraEncryptedBytes), "#2");
			ctx.Assert (output.Size, Is.LessThanOrEqualTo (buffer.Size + host.MaxExtraEncryptedBytes), "#3");
			WriteAndCheckOutput (ctx, DataResult, output);
		}

		[AsyncTest]
		public void TestRecord (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (TestDataName);

			var output = new TlsStream ();
			host.EncryptRecord (ContentType.ApplicationData, buffer, output);

			ctx.Assert (output.Position, Is.GreaterThanOrEqualTo (buffer.Size + host.MinExtraEncryptedBytes + 5), "#2a");
			ctx.Assert (output.Position, Is.LessThanOrEqualTo (buffer.Size + host.MaxExtraEncryptedBytes + 5), "#2b");

			var encryptedSize = host.GetEncryptedSize (buffer.Size);
			ctx.Assert (output.Position, Is.EqualTo (encryptedSize + 5), "#2c");

			output.Position = 0;
			ctx.Assert (output.ReadByte (), Is.EqualTo ((byte)ContentType.ApplicationData), "#4a");
			ctx.Assert (output.ReadInt16 (), Is.EqualTo ((short)TlsProtocolCode.Tls12), "#4b");
			ctx.Assert (output.ReadInt16 (), Is.EqualTo ((short)encryptedSize), "#4c");
			output.Position += encryptedSize;

			WriteAndCheckOutput (ctx, RecordResult, new BufferOffsetSize (output.Buffer, 0, output.Position));
		}

		[AsyncTest]
		public void TestMultiFragment (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			// Padding will push us above the maximum fragment size.
			var size = MAX_FRAGMENT_SIZE - host.MinExtraEncryptedBytes + 1;
			var encryptedSize = host.GetEncryptedSize (size);
			ctx.Assert (encryptedSize, Is.GreaterThan (MAX_FRAGMENT_SIZE));

			var buffer = GetBuffer (MultiFragmentName, 0, size);
			var output = new TlsStream ();
			host.EncryptRecord (ContentType.ApplicationData, buffer, output);
			ctx.Assert (output.Position, Is.GreaterThanOrEqualTo (size + 2 * host.MinExtraEncryptedBytes + 10), "#2a");
			ctx.Assert (output.Position, Is.LessThanOrEqualTo (size + 2 * host.MaxExtraEncryptedBytes + 10), "#2b");
			ctx.Assert (output.Offset, Is.EqualTo (0), "#3");

			output.Position = 0;
			ctx.Assert (output.ReadByte (), Is.EqualTo ((byte)ContentType.ApplicationData), "#4a");
			ctx.Assert (output.ReadInt16 (), Is.EqualTo ((short)TlsProtocolCode.Tls12), "#4b");

			var firstChunkSize = (int)output.ReadInt16 ();
			ctx.Assert (firstChunkSize, Is.GreaterThanOrEqualTo (MAX_FRAGMENT_SIZE - host.MaxExtraEncryptedBytes - 1), "#4c");
			ctx.Assert (firstChunkSize, Is.LessThanOrEqualTo (MAX_FRAGMENT_SIZE), "#4d");

			output.Position += firstChunkSize;

			ctx.Assert (output.ReadByte (), Is.EqualTo ((byte)ContentType.ApplicationData), "#5a");
			ctx.Assert (output.ReadInt16 (), Is.EqualTo ((short)TlsProtocolCode.Tls12), "#5b");

			var secondChunkSize = (int)output.ReadInt16 ();
			ctx.Assert (secondChunkSize, Is.GreaterThanOrEqualTo (encryptedSize - firstChunkSize + host.MinExtraEncryptedBytes), "#5c");
			ctx.Assert (secondChunkSize, Is.LessThanOrEqualTo (encryptedSize - firstChunkSize + host.MaxExtraEncryptedBytes), "#5d");
			output.Position += secondChunkSize;

			WriteAndCheckOutput (ctx, MultiFragmentResult, new BufferOffsetSize (output.Buffer, 0, output.Position));
		}

		[AsyncTest]
		public void TestInputOffset (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var hello = GetBuffer (HelloWorldName);
			var input = new TlsBuffer (hello.Size + MagicDataSize + MagicData2Size);
			input.Write (GetField (MagicDataName));
			var startPos = input.Position;
			input.Write (hello);
			input.Write (GetBuffer (MagicData2Name));

			var output = host.Encrypt (new BufferOffsetSize (input.Buffer, startPos, hello.Size));
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.GreaterThanOrEqualTo (hello.Size + host.MinExtraEncryptedBytes), "#2");
			ctx.Assert (output.Size, Is.LessThanOrEqualTo (hello.Size + host.MaxExtraEncryptedBytes), "#2");
			CheckOutput (ctx, HelloWorldResult, output);
		}

		[AsyncTest]
		public void TestOutputOffset (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input =  GetBuffer (HelloWorldName);

			var output = new TlsBuffer (input.Size + host.MaxExtraEncryptedBytes + MagicDataSize);
			output.Write (GetBuffer (MagicDataName));

			var startOffset = output.Offset;
			var startPos = output.Position;
			var startSize = output.Size;

			var length = host.Encrypt (input, output.GetRemaining ());

			ctx.Assert (length, Is.GreaterThanOrEqualTo (0), "#1");
			ctx.Assert (length, Is.GreaterThanOrEqualTo (input.Size + host.MinExtraEncryptedBytes), "#2a");
			ctx.Assert (length, Is.LessThanOrEqualTo (input.Size + host.MaxExtraEncryptedBytes), "#2a");
			ctx.Assert (output.Offset, Is.EqualTo (startOffset), "#2b");
			ctx.Assert (output.Size, Is.EqualTo (startSize), "#2c");

			output.Position = 0;
			var magic = output.ReadBytes (MagicDataSize);
			ctx.Assert (magic, Is.EqualTo (GetField (MagicDataName)), "#3");

			var encrypted = output.ReadBytes (length);
			CheckOutput (ctx, HelloWorldResult, new BufferOffsetSize (encrypted));
		}


		[AsyncTest]
		public void TestDecrypt (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (HelloWorldResult);
			var output = new TlsBuffer (input.Size);

			var hello = GetField (HelloWorldName);

			var length = host.Decrypt (input, output.GetRemaining ());
			ctx.Assert (length, Is.EqualTo (hello.Length), "#1");

			output.Position = 0;
			var decrypted = output.ReadBytes (length);
			ctx.Assert (decrypted, Is.EqualTo (hello), "#4");
		}

		[AsyncTest]
		public void TestDecryptData0 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (Data0Result);
			var output = host.Decrypt (input);

			ctx.Assert (output.Size, Is.EqualTo (0), "#1");
		}

		[AsyncTest]
		public void TestDecryptData11 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (Data11Result);
			var output = host.Decrypt (input);

			ctx.Assert (output.Size, Is.EqualTo (11), "#1");
			ctx.Assert (TlsBuffer.Compare (output, GetBuffer (TestDataName, 0, 11)), "#2");
		}

		[AsyncTest]
		public void TestDecryptData12 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (Data12Result);
			var output = host.Decrypt (input);

			ctx.Assert (output.Size, Is.EqualTo (12), "#1");
			ctx.Assert (TlsBuffer.Compare (output, GetBuffer (TestDataName, 0, 12)), "#2");
		}

		[AsyncTest]
		public void TestDecryptData13 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (Data13Result);
			var output = host.Decrypt (input);

			ctx.Assert (output.Size, Is.EqualTo (13), "#1");
			ctx.Assert (TlsBuffer.Compare (output, GetBuffer (TestDataName, 0, 13)), "#2");
		}

		[AsyncTest]
		public void TestDecryptData (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (DataResult);
			var output = host.Decrypt (input);

			var data = GetBuffer (TestDataName);

			ctx.Assert (output.Size, Is.EqualTo (data.Size), "#1");
			ctx.Assert (TlsBuffer.Compare (output, data), "#2");
		}

		[AsyncTest]
		public void TestEncryptWithExtraPadding (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var buffer = GetBuffer (TestDataName);
			IBufferOffsetSize output;
			try {
				host.Parameters.ExtraPaddingBlocks = 13;
				output = host.Encrypt (buffer);
			} finally {
				host.Parameters.ExtraPaddingBlocks = 0;
			}

			var extraPadding = 13 * 16;
			ctx.Assert (output, Is.Not.Null, "#1");
			ctx.Assert (output.Size, Is.GreaterThanOrEqualTo (buffer.Size + extraPadding + host.MinExtraEncryptedBytes), "#2");
			ctx.Assert (output.Size, Is.LessThanOrEqualTo (buffer.Size + extraPadding + host.MaxExtraEncryptedBytes), "#3");
			WriteAndCheckOutput (ctx, ExtraPaddingResult, output);
		}

		[AsyncTest]
		public void TestDecryptWithExtraPadding (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (ExtraPaddingResult);
			var output = host.Decrypt (input);

			var data = GetBuffer (TestDataName);

			ctx.Assert (output.Size, Is.EqualTo (data.Size), "#1");
			ctx.Assert (TlsBuffer.Compare (output, data), "#2");
		}

		[AsyncTest]
		public void TestDecryptWithInvalidPadding (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (ExtraPaddingResult);

			var modified = new TlsBuffer (input.Size);
			modified.Write (input.Buffer);

			var theOffset = modified.Size - (2 * host.BlockSize) - 5;
			modified.Buffer [theOffset] ^= 0x01;

			input = new BufferOffsetSize (modified.Buffer, 0, modified.Size);

			try {
				host.Decrypt (input);
				ctx.AssertFail ("#1");
			} catch (Exception ex) {
				ctx.Assert (ex, Is.InstanceOf<TlsException> (), "#2");
				var tlsEx = (TlsException)ex;
				ctx.Assert (tlsEx.Alert.Level, Is.EqualTo (AlertLevel.Fatal), "#3");
				ctx.Assert (tlsEx.Alert.Description, Is.EqualTo (AlertDescription.BadRecordMAC), "#4");
			}
		}

		[AsyncTest]
		public void TestDecryptWithInvalidPadding2 (TestContext ctx, [TestHost] IEncryptionTestHost host)
		{
			var input = GetBuffer (Data11Result);

			var modified = new TlsBuffer (input.Size);
			modified.Write (input.Buffer);

			// Flip a bit in the last byte, this will affect the padding size.
			modified.Buffer [modified.Size - 1] ^= 0x01;

			input = new BufferOffsetSize (modified.Buffer, 0, modified.Size);

			try {
				host.Decrypt (input);
				ctx.AssertFail ("#1");
			} catch (Exception ex) {
				ctx.Assert (ex, Is.InstanceOf<TlsException> (), "#2");
				var tlsEx = (TlsException)ex;
				ctx.Assert (tlsEx.Alert.Level, Is.EqualTo (AlertLevel.Fatal), "#3");
				ctx.Assert (tlsEx.Alert.Description, Is.EqualTo (AlertDescription.BadRecordMAC), "#4");
			}
		}
	}
}
