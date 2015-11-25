using System;
using System.Runtime.CompilerServices;
using Mono.Security.Interface;

[assembly: TypeForwardedTo (typeof (Alert))]
[assembly: TypeForwardedTo (typeof (AlertLevel))]
[assembly: TypeForwardedTo (typeof (AlertDescription))]
[assembly: TypeForwardedTo (typeof (CipherAlgorithmType))]
[assembly: TypeForwardedTo (typeof (CipherSuiteCode))]
[assembly: TypeForwardedTo (typeof (ExchangeAlgorithmType))]
[assembly: TypeForwardedTo (typeof (HashAlgorithmType))]
[assembly: TypeForwardedTo (typeof (MonoTlsConnectionInfo))]

[assembly: TypeForwardedTo (typeof (IBufferOffsetSize))]
[assembly: TypeForwardedTo (typeof (TlsException))]
[assembly: TypeForwardedTo (typeof (TlsProtocolCode))]
[assembly: TypeForwardedTo (typeof (TlsProtocols))]
