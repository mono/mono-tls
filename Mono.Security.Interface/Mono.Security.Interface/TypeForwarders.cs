using System;
using System.Runtime.CompilerServices;
using SSA = System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
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

[assembly: TypeForwardedTo (typeof (SSA.SslProtocols))]

[assembly: TypeForwardedTo (typeof (X509Certificate))]
[assembly: TypeForwardedTo (typeof (X509ContentType))]
[assembly: TypeForwardedTo (typeof (X509KeyStorageFlags))]
