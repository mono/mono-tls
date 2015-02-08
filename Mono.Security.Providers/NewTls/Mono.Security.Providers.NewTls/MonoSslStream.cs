#if NEW_MONO_API
extern alias MonoSecurity;
using System;
using System.IO;
using System.Net.Security;
using System.Threading.Tasks;
using MonoSecurity::Mono.Security.Protocol.NewTls;

namespace Mono.Security.NewMonoSource
{
    public class MonoSslStream : SslStream
    {
        internal MonoSslStream(Stream innerStream, TlsSettings settings)
            : this(innerStream, false, null, null, settings)
        {
        }

        internal MonoSslStream(Stream innerStream, bool leaveOpen, TlsSettings settings)
            : this(innerStream, leaveOpen, null, null, EncryptionPolicy.RequireEncryption, settings)
        {
        }

        internal MonoSslStream(Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, TlsSettings settings)
            : this(innerStream, leaveOpen, certValidationCallback, null, EncryptionPolicy.RequireEncryption, settings)
        {
        }

        internal MonoSslStream(Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, 
                        LocalCertificateSelectionCallback certSelectionCallback, TlsSettings settings)
            : this(innerStream, leaveOpen, certValidationCallback, certSelectionCallback, EncryptionPolicy.RequireEncryption, settings)
        {
        }

        internal MonoSslStream(Stream innerStream, bool leaveOpen, RemoteCertificateValidationCallback certValidationCallback, 
                        LocalCertificateSelectionCallback certSelectionCallback, EncryptionPolicy encryptionPolicy, TlsSettings settings)
            : base(innerStream, leaveOpen, certValidationCallback, certSelectionCallback, encryptionPolicy, ConvertSettings(settings))
        {
        }

        public bool IsClosed
        {
            get { return base.IsClosed; }
        }

        public TlsException LastError
        {
            get { return (TlsException)base.LastError; }
        }

        public Task Shutdown(bool waitForReply)
        {
            return Task.Factory.FromAsync((state,result) => BeginShutdown (waitForReply, state, result), EndShutdown, null);
        }

        static SSPIConfiguration ConvertSettings(TlsSettings settings)
        {
            return settings != null ? new MyConfiguration(settings) : null;
        }

        class MyConfiguration : SSPIConfiguration
        {
            TlsSettings settings;

            public MyConfiguration(TlsSettings settings)
            {
                this.settings = settings;
            }

            public TlsSettings Settings {
                get { return settings; }
            }
        }
    }
}
#endif

