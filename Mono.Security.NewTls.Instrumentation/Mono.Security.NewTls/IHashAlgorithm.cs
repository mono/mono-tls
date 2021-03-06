using System;
using Mono.Security.Interface;

namespace Mono.Security.NewTls
{
	public interface IHashAlgorithm : IDisposable
	{
		int HashSize {
			get;
		}

		HashAlgorithmType Algorithm {
			get;
		}

		void TransformBlock (byte[] inputBuffer, int inputOffset, int inputCount);

		byte[] GetRunningHash ();

		void Reset ();
	}
}
