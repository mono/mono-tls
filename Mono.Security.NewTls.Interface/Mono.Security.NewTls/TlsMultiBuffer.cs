using System;
using System.Collections.Generic;

namespace Mono.Security.NewTls
{
	public class TlsMultiBuffer
	{
		MemoryChunk first, last;

		private class MemoryChunk : BufferOffsetSize
		{
			public MemoryChunk next;

			public MemoryChunk (byte[] buffer, int offset, int size)
				: base (buffer, offset, size)
			{
			}
		}

		public bool IsEmpty {
			get { return first == null; }
		}

		public bool IsSingle {
			get { return first != null && first.next == null; }
		}

		public void Add (TlsBuffer buffer)
		{
			Add (buffer.Buffer, buffer.Offset, buffer.Size);
		}

		public void Add (byte[] buffer)
		{
			Add (buffer, 0, buffer.Length);
		}

		public void Add (byte[] buffer, int offset, int size)
		{
			var chunk = new MemoryChunk (buffer, offset, size);
			if (last == null)
				first = last = chunk;
			else {
				last.next = chunk;
				last = chunk;
			}
		}

		public BufferOffsetSize[] GetBufferArray ()
		{
			int count = 0;
			for (var ptr = first; ptr != null; ptr = ptr.next)
				count++;
			var array = new BufferOffsetSize [count];
			count = 0;
			for (var ptr = first; ptr != null; ptr = ptr.next)
				array [count++] = ptr;
			return array;
		}

		public void Clear ()
		{
			for (var ptr = first; ptr != null; ptr = ptr.next)
				ptr.Dispose ();
			first = last = null;
		}

		public BufferOffsetSize GetBuffer ()
		{
			int totalSize = 0;
			for (var ptr = first; ptr != null; ptr = ptr.next)
				totalSize += ptr.Size;

			var outBuffer = new BufferOffsetSize (new byte [totalSize]);
			int offset = 0;
			for (var ptr = first; ptr != null; ptr = ptr.next) {
				Buffer.BlockCopy (ptr.Buffer, ptr.Offset, outBuffer.Buffer, offset, ptr.Size);
				offset += ptr.Size;
			}
			return outBuffer;
		}

		public BufferOffsetSize StealBuffer ()
		{
			if (IsSingle) {
				var retval = first;
				first = last = null;
				return retval;
			}

			return GetBuffer ();
		}
	}
}

