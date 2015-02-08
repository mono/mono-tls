using System;
using Mono.Security.Interface;

namespace Mono.Security.Protocol.NewTls
{
	public class BufferOffsetSize : SecretParameters, IBufferOffsetSize
	{
		public byte[] Buffer {
			get;
			private set;
		}

		public int Offset {
			get;
			internal set;
		}

		public int Size {
			get { return EndOffset - Offset; }
		}

		public int EndOffset {
			get;
			internal set;
		}

		public BufferOffsetSize (byte[] buffer, int offset, int size)
		{
			Buffer = buffer;
			Offset = offset;
			EndOffset = offset + size;
		}

		public BufferOffsetSize (byte[] buffer)
			: this (buffer, 0, buffer.Length)
		{
		}

		public BufferOffsetSize (int size)
			: this (new byte [size])
		{
		}

		internal void TruncateTo (int newSize)
		{
			if (newSize > Size)
				throw new ArgumentException ("newSize");
			EndOffset = Offset + newSize;
		}

		protected void SetBuffer (byte[] buffer, int offset, int size)
		{
			Buffer = buffer;
			Offset = offset;
			EndOffset = offset + size;
		}

		protected override void Clear ()
		{
			Buffer = null;
			Offset = EndOffset = 0;
		}
	}
}

