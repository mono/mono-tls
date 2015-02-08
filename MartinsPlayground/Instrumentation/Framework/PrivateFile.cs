using System;
using System.IO;

namespace Mono.Security.Instrumentation.Framework
{
	public abstract class PrivateFile : IDisposable
	{
		string filename;
		byte[] data;

		public string Password {
			get;
			private set;
		}

		public PrivateFile (string filename, string password)
		{
			this.filename = filename;
			Password = password;
		}

		public PrivateFile (byte[] data, string password)
		{
			this.data = data;
			Password = password;
		}

		public byte[] Data {
			get {
				if (data == null)
					data = ReadFromFile (filename);
				return data;
			}
		}

		public string FileName {
			get {
				if (filename == null)
					filename = WriteToTempFile (data);
				return filename;
			}
		}

		static byte[] ReadFromFile (string path)
		{
			using (var stream = new FileStream (path, FileMode.Open)) {
				var buffer = new byte [stream.Length];
				var ret = stream.Read (buffer, 0, buffer.Length);
				if (ret != buffer.Length)
					throw new IOException ();
				return buffer;
			}
		}

		static string WriteToTempFile (byte[] bytes)
		{
			var path = Path.GetTempFileName ();
			using (var stream = new FileStream (path, FileMode.Create, FileAccess.Write))
				stream.Write (bytes, 0, bytes.Length);
			return path;
		}

		void DeleteFile (string filename)
		{
			try {
				if (File.Exists (filename))
					File.Delete (filename);
			} catch {
			}
		}

		public void Dispose ()
		{
			Dispose (true);
			GC.SuppressFinalize (this);
		}

		protected virtual void Dispose (bool disposing)
		{
			if (data != null) {
				Array.Clear (data, 0, data.Length);
				data = null;
			}
			Password = null;
			if (filename != null) {
				DeleteFile (filename);
				filename = null;
			}
		}

		~PrivateFile ()
		{
			Dispose (false);
		}
	}
}

