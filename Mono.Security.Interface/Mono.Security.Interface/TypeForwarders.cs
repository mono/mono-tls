using System;
using System.Collections;
using System.Net.Security;
using System.Runtime.CompilerServices;
using SSA = System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Mono.Security.Interface;

#region New Mono 4.3.1 APIs

[assembly: TypeForwardedTo (typeof (Alert))]
[assembly: TypeForwardedTo (typeof (AlertLevel))]
[assembly: TypeForwardedTo (typeof (AlertDescription))]
[assembly: TypeForwardedTo (typeof (CipherAlgorithmType))]
[assembly: TypeForwardedTo (typeof (CipherSuiteCode))]
[assembly: TypeForwardedTo (typeof (ExchangeAlgorithmType))]
[assembly: TypeForwardedTo (typeof (HashAlgorithmType))]
[assembly: TypeForwardedTo (typeof (MonoTlsConnectionInfo))]
[assembly: TypeForwardedTo (typeof (IMonoSslStream))]

[assembly: TypeForwardedTo (typeof (IBufferOffsetSize))]
[assembly: TypeForwardedTo (typeof (TlsException))]
[assembly: TypeForwardedTo (typeof (TlsProtocolCode))]
[assembly: TypeForwardedTo (typeof (TlsProtocols))]

#endregion

#region .NET 4.5 APIs

[assembly: TypeForwardedTo (typeof (SSA.CipherAlgorithmType))]
[assembly: TypeForwardedTo (typeof (SSA.ExchangeAlgorithmType))]
[assembly: TypeForwardedTo (typeof (SSA.HashAlgorithmType))]
[assembly: TypeForwardedTo (typeof (SSA.SslProtocols))]

[assembly: TypeForwardedTo (typeof (CollectionBase))]

[assembly: TypeForwardedTo (typeof (AuthenticatedStream))]

[assembly: TypeForwardedTo (typeof (X509Certificate))]
[assembly: TypeForwardedTo (typeof (X509CertificateCollection))]
[assembly: TypeForwardedTo (typeof (X509Chain))]
[assembly: TypeForwardedTo (typeof (X509ContentType))]
[assembly: TypeForwardedTo (typeof (X509KeyStorageFlags))]

#endregion
